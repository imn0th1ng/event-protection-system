fx_version 'cerulean'
game 'gta5'

author 'n0thing'
description 'Its a free and secure event protection system.'
version '1.0.0'
shared_scripts {
    'libs/sha.lua',
    'libs/util.lua',
    'libs/gf.lua',
    'libs/aes.lua',
    'libs/buffer.lua',
    'libs/ciphermode.lua',
    'libs/aeslua.lua',
    'utils.lua'
}

client_scripts {
    "client.lua"
}

server_scripts {
    "server.lua"
}

lua54 'yes'