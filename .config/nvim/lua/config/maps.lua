local setmap = vim.keymap.set

setmap('i', 'jk', '<ESC>', {})
setmap('n', '<C-s>', ':w<CR>', {})
setmap('n', 'mm', 'gt', {})
setmap('n', 'zz', 'gT', {})
setmap('n', '<ESC>', ':noh<CR>', {silent=true})

setmap('n', 'tt', '$byw<ESC>^v$hp^iconst/4 <ESC>A, 0x1', {silent=true})
setmap('n', 'tl', '0f:lyw0gf:<C-r>"<CR>^v$', {silent=true})
