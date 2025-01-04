--local M = {
--  'neoclide/coc.nvim',
--  branch = 'release',
--  build = 'npm ci',
--}
--
--M.config = function()
--  --require('coconfig')
--end

  --{
  --  "williamboman/mason.nvim",
	--	config = function()
	--		require('mason').setup{}
	--	end
	--},
  --{
	--	"williamboman/mason-lspconfig.nvim",
	--	config = function()
	--		require('mason-lspconfig').setup{}
	--	end
	--},

return {
	"neovim/nvim-lspconfig",
	config = function()
		local lsp = require('lspconfig')
		local servers = { 'clangd' }
    for _, s in ipairs(servers) do
	    lsp[s].setup {}
		end
	end
}
