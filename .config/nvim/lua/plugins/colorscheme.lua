return {
    "catppuccin/nvim",
    name = "catppuccin",
    priority = 1000,
    config = function()
        vim.cmd[[
        colo catppuccin
        ]]
    end
}

--return {
--  'Shatur/neovim-ayu',
--  config = function()
--    require('ayu').setup({
--      mirage = false,
--      terminal = true,
--      overrides = {},
--    })
--    vim.cmd[[
--      colo ayu-dark
--    ]]
--  end
--}
