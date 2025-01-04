alias c=clear
alias l=ls
alias la='ls -a'
alias lah='ls -lah'
alias x=exit
alias bashrc='vi ~/.bashrc'
alias alisa='vi ~/.bash_aliases'
alias which='command -v'
alias tclips='termux-clipboard-set'
alias tclipg='termux-clipboard-get'

[ -f $PREFIX/bin/bat ] && {
	alias cat='bat -Pp --theme TwoDark'
}

fcopy() {
	cat "$1" | termux-clipboard-set
}

