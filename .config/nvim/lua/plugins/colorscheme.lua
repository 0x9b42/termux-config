return {
  'Shatur/neovim-ayu',
  config = function()
    require('ayu').setup({
      mirage = false,
      terminal = true,
      overrides = {},
    })
    vim.cmd[[
      colo ayu-dark
    ]]
  end
}
