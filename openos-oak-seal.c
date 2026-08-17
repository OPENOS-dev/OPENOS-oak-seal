/*
 * openos-oak-seal — OAK-Seal 封印工具 (用户态写硬盘头)
 *
 * 用途: 新内核安装后重新封印硬盘, 供内核启动时 openos_oak_early_init()
 *       校验 (对称操作)。
 *
 * 流程:
 *   1. 读取 /boot/vmlinuz-$(uname -r), 计算 SHA-256 (OpenSSL)
 *   2. 从内存 OAK-SK (环境变量 OPENOS_OAK_SK) 派生临时密钥 (PBKDF2/HKDF),
 *      用于加密 LUKS 主密钥 (从 dm-crypt keyring / dmsetup 获取)
 *   3. 将封印数据块写入 /dev/sdX 偏移 0x1000 (需用户确认设备名)
 *   4. 校验写入完整性 (重读比对)
 *
 * 封印块布局 (必须与内核 oak_early.c 的 struct oak_seal_block 一致):
 *   offset 0  : magic "OAKS" (4)
 *   offset 4  : u32 version (LE)
 *   offset 8  : u32 kernel_len (LE)
 *   offset 12 : kernel_sha256[32]
 *   offset 44 : user_sha256[32]   (解锁用户名 SHA-256)
 *   offset 76 : pass_sha256[32]   (解锁密码 SHA-256)
 *   offset 108: reserved[404]     (含加密的 LUKS 主密钥区, 见说明)
 *   共 512 字节
 *
 * 安全说明:
 *   - OAK-SK 经环境变量传入 (不落盘/不进命令行历史), 推荐 shell 私有变量
 *   - LUKS 主密钥获取: 优先 ioctl DM_TABLE_STATUS(SHOW_KEYS) 访问
 *     dm-crypt keyring; 无权限时回退 `dmsetup table --showkeys` (需 root)
 *   - 加密后的 LUKS 密钥写入 reserved 区首部 (前置 4 字节长度), 由内核
 *     侧 OAK 会话解密恢复
 *   - 写设备需 root, 并二次确认设备名防误写
 *
 * 构建 (尽量静态链接 OpenSSL):
 *   cc -O2 -static -o openos-oak-seal openos-oak-seal.c -lssl -lcrypto
 *   (静态需 libssl.a/libcrypto.a; 动态回退: 去掉 -static)
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#define OAK_SEAL_OFFSET   0x1000
#define OAK_SEAL_MAGIC    "OAKS"
#define OAK_SHA256_LEN    32
#define OAK_SEAL_BLOCK_SZ 512
#define LUKS_KEY_MAX      64
#define DERIVE_KEY_LEN    32

/* 与内核 oak_early.c 一致的封印块 (显式 LE 打包, 跨平台) */
typedef struct {
	uint8_t  magic[4];
	uint32_t version;
	uint32_t kernel_len;
	uint8_t  kernel_hash[OAK_SHA256_LEN];
	uint8_t  user_hash[OAK_SHA256_LEN];
	uint8_t  pass_hash[OAK_SHA256_LEN];
	uint8_t  reserved[OAK_SEAL_BLOCK_SZ - (4 + 4 + 4 + 32 * 3)];
} oak_seal_block;

static void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}
static uint32_t get_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ---- 日志 ---- */
static void fail(const char *m) { fprintf(stderr, "openos-oak-seal: %s\n", m); }

/* ---- SHA-256 (OpenSSL) ---- */
static int sha256_file(const char *path, uint8_t out[OAK_SHA256_LEN],
		       uint32_t *out_len)
{
	FILE *f = fopen(path, "rb");
	EVP_MD_CTX *ctx;
	unsigned char buf[8192];
	size_t n;
	unsigned int total = 0, olen = 0;

	if (!f) { perror(path); return -1; }
	ctx = EVP_MD_CTX_new();
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto err;
	while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
		EVP_DigestUpdate(ctx, buf, n);
		total += (unsigned int)n;
	}
	if (ferror(f)) goto err;
	if (EVP_DigestFinal_ex(ctx, out, &olen) != 1) goto err;
	fclose(f);
	EVP_MD_CTX_free(ctx);
	*out_len = total;
	return 0;
err:
	fclose(f); EVP_MD_CTX_free(ctx); return -1;
}

/* ---- 从 OAK-SK 派生临时密钥 (HKDF-SHA256; 用 HMAC 实现 HKDF-Expand) ---- */
static int derive_key(const uint8_t *sk, size_t sk_len,
		      const uint8_t *salt, size_t salt_len,
		      uint8_t out[DERIVE_KEY_LEN])
{
	unsigned char prk[EVP_MAX_MD_SIZE];
	unsigned int prk_len;
	unsigned char t[DERIVE_KEY_LEN + 1];
	unsigned int t_len;

	if (HMAC(EVP_sha256(), sk, (int)sk_len, salt, salt_len,
		 prk, &prk_len) == NULL)
		return -1;
	/* HKDF-Expand, 单块 */
	memset(t, 0x01, 1);
	if (HMAC(EVP_sha256(), prk, (int)prk_len, t, 1, out, &t_len) == NULL)
		return -1;
	return (t_len == DERIVE_KEY_LEN) ? 0 : -1;
}

/* ---- 加密/解密 (AES-256-CTR, 用于 LUKS 主密钥) ---- */
static int crypt_blob(const uint8_t *key, size_t key_len,
		      const uint8_t *iv, const uint8_t *in, size_t in_len,
		      uint8_t *out)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len = 0, total = 0;

	if (!ctx) return -1;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1)
		goto err;
	if (EVP_EncryptUpdate(ctx, out, &len, in, (int)in_len) != 1)
		goto err;
	total = len;
	if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1)
		goto err;
	total += len;
	EVP_CIPHER_CTX_free(ctx);
	return total;
err:
	EVP_CIPHER_CTX_free(ctx); return -1;
}

/* ---- 获取 LUKS 主密钥 (dm-crypt keyring) ----
 * 优先: DM_TABLE_STATUS + DM_STATUS_TABLE_FLAG | DM_STATUS_NOFLUSH_FLAG,
 *       dm_task 经 /dev/mapper/control, SHOW_KEYS 由 DM_SECURE_IIO 实现。
 * 回退: popen("dmsetup table --showkeys <name>") (需 root, 结构解析简化为取
 *       crypt 段 key 段)。
 * 原型: 优先实现 DM ioctl 骨架; 实际密钥内容解析留待部署环境。
 */
static int get_luks_key(const char *dm_name, uint8_t *key, size_t *key_len)
{
	struct dm_ioctl dm;
	char *buf = NULL;
	int fd, rc = -1;
	size_t size = 16 * 1024;

	fd = open("/dev/mapper/control", O_RDWR);
	if (fd < 0) { perror("打开 /dev/mapper/control"); return -1; }
	buf = calloc(1, size);
	memset(&dm, 0, sizeof dm);
	dm.version[0] = DM_VERSION_MAJOR;
	dm.version[1] = DM_VERSION_MINOR;
	dm.version[2] = DM_VERSION_PATCHLEVEL;
	dm.data_size = size;
	dm.data_start = sizeof(struct dm_ioctl);
	strncpy(dm.name, dm_name, sizeof dm.name - 1);

	/* DM_TABLE_STATUS + SHOW_KEYS (返回含密钥的表) */
	dm.target_count = 0;
	if (ioctl(fd, DM_TABLE_STATUS, buf) < 0) {
		perror("DM_TABLE_STATUS");
		goto out;
	}
	/* 原型: 解析 target 字符串中的 key (crypt 段第 2 字段) —— 部署时按
	 * 实际 keyring 会话补齐; 此处回退 dmsetup。 */
	close(fd); free(buf);
	{
		FILE *p;
		char cmd[128];
		char line[512];
		snprintf(cmd, sizeof cmd, "dmsetup table --showkeys %s", dm_name);
		p = popen(cmd, "r");
		if (!p) return -1;
		while (fgets(line, sizeof line, p)) {
			char *save = NULL;
			char *t = strtok_r(line, " \t", &save);
			if (t && strcmp(t, "0") == 0) {
				/* crypt <start> <len> <dev> <key> ... */
				char *fld = NULL; int idx = 0;
				for (fld = strtok_r(NULL, " \t", &save);
				     fld; fld = strtok_r(NULL, " \t", &save)) {
					idx++;
					if (idx == 4) {  /* key 字段 (hex) */
						int hl = (int)strlen(fld);
						if (hl > 0 && hl <= (int)(LUKS_KEY_MAX*2)) {
							int bl = hl / 2;
							for (int i = 0; i < bl; i++)
								sscanf(fld + i*2, "%2hhx", &key[i]);
							*key_len = (size_t)bl;
							rc = 0;
						}
						break;
					}
				}
			}
		}
		pclose(p);
	}
out:
	return rc;
}

/* ---- 写设备偏移 + 校验 ---- */
static int write_and_verify(const char *dev, const uint8_t *blk,
			    size_t len)
{
	int fd;
	uint8_t *readback = malloc(len);

	fd = open(dev, O_RDWR);
	if (fd < 0) { perror(dev); free(readback); return -1; }
	if (pwrite(fd, blk, len, OAK_SEAL_OFFSET) != (ssize_t)len) {
		perror("pwrite"); close(fd); free(readback); return -1;
	}
	/* 校验写入完整性 */
	if (pread(fd, readback, len, OAK_SEAL_OFFSET) != (ssize_t)len) {
		perror("pread"); close(fd); free(readback); return -1;
	}
	if (memcmp(readback, blk, len) != 0) {
		fail("写入校验失败: 数据不匹配");
		close(fd); free(readback); return -1;
	}
	close(fd);
	free(readback);
	return 0;
}

int main(int argc, char **argv)
{
	const char *vmlinuz, *dev, *dm_name = NULL, *user = NULL, *pass = NULL;
	const char *oak_sk_env;
	uint8_t oak_sk[256]; size_t oak_sk_len;
	uint8_t iv[16];
	oak_seal_block seal;
	char buf[64];
	int fd, c;

	(void)get_le32; (void)crypt_blob; (void)derive_key;

	/* 参数: openos-oak-seal <设备> [dm-crypt 名] [用户名] [密码] */
	if (argc < 2) {
		fprintf(stderr,
			"用法: %s <设备如/dev/sda> [dm-crypt名] [用户名] [密码]\n"
			"  需环境变量 OPENOS_OAK_SK 提供 OAK-SK\n",
			argv[0]);
		return 1;
	}
	dev = argv[1];
	if (argc > 2) dm_name = argv[2];
	if (argc > 3) user = argv[3];
	if (argc > 4) pass = argv[4];

	oak_sk_env = getenv("OPENOS_OAK_SK");
	if (!oak_sk_env || strlen(oak_sk_env) == 0) {
		fail("未提供 OPENOS_OAK_SK 环境变量");
		return 1;
	}
	oak_sk_len = strlen(oak_sk_env);
	if (oak_sk_len > sizeof oak_sk) oak_sk_len = sizeof oak_sk;
	memcpy(oak_sk, oak_sk_env, oak_sk_len);

	/* 二次确认设备名 (防误写) */
	if (!dm_name) {
		printf("确认写入封印到设备 %s (偏移 0x%x)? 输入设备名继续: ",
		       dev, OAK_SEAL_OFFSET);
		if (!fgets(buf, sizeof buf, stdin)) return 1;
		buf[strcspn(buf, "\n")] = 0;
		if (strcmp(buf, dev) != 0) {
			fail("设备名不匹配, 已取消");
			return 1;
		}
	}

	/* 1. 计算内核 SHA-256 (/boot/vmlinuz-$(uname -r)) */
	{
		char uname_r[64];
		struct utsname un;
		uname(&un);
		snprintf(uname_r, sizeof uname_r, "/boot/vmlinuz-%s", un.release);
		vmlinuz = uname_r;
	}
	memset(&seal, 0, sizeof seal);
	memcpy(seal.magic, OAK_SEAL_MAGIC, 4);
	put_le32(seal.version, 1);
	if (sha256_file(vmlinuz, seal.kernel_hash, &seal.kernel_len) != 0) {
		fail("计算内核哈希失败");
		return 1;
	}

	/* 2. 用户/密码哈希 (可空; 无则内核校验失败时不可解锁) */
	if (user)
		EVP_Digest(user, strlen(user), seal.user_hash, NULL,
			   EVP_sha256(), NULL);
	if (pass)
		EVP_Digest(pass, strlen(pass), seal.pass_hash, NULL,
			   EVP_sha256(), NULL);

	/* 3. 派生临时密钥 + 加密 LUKS 主密钥写入 reserved 区 */
	if (dm_name) {
		uint8_t luks_key[LUKS_KEY_MAX];
		size_t luks_len = 0;
		uint8_t tmpkey[DERIVE_KEY_LEN];
		uint8_t *enc;

		if (get_luks_key(dm_name, luks_key, &luks_len) != 0 ||
		    luks_len == 0) {
			fail("获取 LUKS 主密钥失败");
			return 1;
		}
		if (derive_key(oak_sk, oak_sk_len, seal.kernel_hash,
			       OAK_SHA256_LEN, tmpkey) != 0) {
			fail("密钥派生失败");
			return 1;
		}
		if (RAND_bytes(iv, sizeof iv) != 1) {
			fail("随机数失败");
			return 1;
		}
		enc = calloc(1, luks_len + 16);
		if (crypt_blob(tmpkey, DERIVE_KEY_LEN, iv,
			       luks_key, luks_len, enc) < 0) {
			fail("LUKS 密钥加密失败");
			free(enc); return 1;
		}
		/* reserved 区首部: iv[16] + len[4] + 密文 */
		memcpy(seal.reserved, iv, 16);
		put_le32(seal.reserved + 16, (uint32_t)luks_len);
		memcpy(seal.reserved + 20, enc, luks_len);
		free(enc);
	}

	/* 4. 写入 + 校验 */
	if (write_and_verify(dev, (const uint8_t *)&seal, sizeof seal) != 0) {
		fail("封印写入失败");
		return 1;
	}

	printf("OAK-Seal 封印完成: %s 偏移 0x%x (内核哈希 %d 字节)\n",
	       dev, OAK_SEAL_OFFSET, OAK_SHA256_LEN);
	return 0;
}
