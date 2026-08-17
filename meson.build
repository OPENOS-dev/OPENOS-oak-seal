# openos-oak-seal — OAK-Seal 封印工具 (写硬盘头)
project('openos-oak-seal', 'c', default_options: ['c_std=c11'])

openssl = dependency('openssl')

executable('openos-oak-seal',
  sources: ['openos-oak-seal.c'],
  dependencies: [openssl],
  install: true)
