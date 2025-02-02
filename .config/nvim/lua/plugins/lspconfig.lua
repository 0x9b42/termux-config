local mason = {
    "williamboman/mason.nvim",
    config = function()
        require('mason').setup{}
    end
}

local masonlsp = {
    "williamboman/mason-lspconfig.nvim",
    config = function()
        require('mason-lspconfig').setup{}
    end
}

local nvimlsp = {
    "neovim/nvim-lspconfig",
    config = function()
        vim.diagnostic.config({
            virtual_text = false,
            --{
            --    --prefix = '', -- ● ■ ▎ x
            --},
            signs = {
                text = {
                    [vim.diagnostic.severity.ERROR] = "",
                    [vim.diagnostic.severity.WARN] = "",
                    [vim.diagnostic.severity.INFO] = "",
                    [vim.diagnostic.severity.HINT] = "",
                },
            },
        })

        local lsp = require('lspconfig')
        local servers = { 'clangd', 'pyright', 'jdtls'}
        for _, s in ipairs(servers) do
            lsp[s].setup {}
        end
    end
}

local lspline = {
    "ErichDonGubler/lsp_lines.nvim",
    config = function()

        require("lsp_lines").setup()

        vim.keymap.set(
            "",
            "<Leader>l",
            require("lsp_lines").toggle,
            { desc = "Toggle lsp_lines" }
        )
    end,
}



return {
    mason,
    masonlsp,
    nvimlsp,
    lspline,
}
