alias c=clear
alias l=ls
alias la='ls -a'
alias lah='ls -lah'
alias q=exit
alias bashrc='vi ~/.bashrc'
alias alisa='vi ~/.bash_aliases'
alias which='command -v'
alias tclips='termux-clipboard-set'
alias tclipg='termux-clipboard-get'

alias r2='r2 -e bin.relocs.apply=true'

[ -f $PREFIX/bin/bat ] && {
	alias cat='bat -Pp --theme TwoDark'
}

fcopy() {
	cat "$1" | termux-clipboard-set
}

