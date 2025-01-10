vim.cmd [[

set nonumber rnu signcolumn=yes
set tabstop=4 shiftwidth=4 softtabstop=4
set expandtab smarttab
set noswapfile hidden
set ignorecase smartcase
set fillchars=eob:\ 

set background=dark
colo retrobox
hi Normal guibg=NONE
hi SignColumn guibg=NONE

set statusline=%f%m%r\ %=0x%O\ %b\ 0x%B\ %=%l:%c\ %L

command! Smali2Java let @a=expand('%:r') | tabe | execute 'read !smalitojava ' . @a . '.smali' | execute 'edit ' . @a . '.java'

"command! Smali2Java let @a=expand('%:r') | tabnew | !smalitojava shellescape(@a . '.smali') | file shellescape(@a . '.java')


]]
