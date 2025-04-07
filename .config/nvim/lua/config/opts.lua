vim.cmd [[

set nonumber rnu signcolumn=yes
set tabstop=2 shiftwidth=2 softtabstop=2
set expandtab smarttab
set noswapfile hidden
set ignorecase smartcase
set fillchars=eob:\ 

set background=dark
"colo retrobox
hi Normal guibg=NONE
hi SignColumn guibg=NONE
"hi LineNr guifg=#696969

set statusline=%f%m%r\ %=0x%O\ %b\ 0x%B\ %=%l:%c\ %L

command! Smali2Java let @a=expand('%:r') | tabe | execute 'read !smalitojava ' . @a . '.smali' | execute 'edit ' . @a . '.java'

nnoremap <silent>tm :tabe<cr>:set nonu nornu signcolumn=no<cr>:term<cr>aproot bash<cr>clear;$ANDROID_NDK_ROOT/ndk-build&&exit<cr>clear;bash build.sh&&exit<cr>

command! RunBuild echo 'running build ...' | normal! tm
"command! RunBuild call feedkeys('tm', 'n')

]]
