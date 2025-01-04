# unlimited history
HISTSIZE=
HISTFILESIZE=

# unique command history
HISTCONTROL=erasedups

alya=(
    ~/.bash_aliases
    ~/android/tools/apktools.sh
    ~/.local/tools/ffmpegtools.sh
)
for i in ${alya[@]}
do
    [ -f $i ] && . $i
done
unset alya

PATH="~/.local/bin:$PATH"

# android sdk
PATH="~/android/sdk/build-tools/34.0.4:$PATH"
PATH="~/android/sdk/cmdline-tools/latest/bin:$PATH"
PATH="~/android/sdk/platform-tools:$PATH"

export PATH

PS1='\[\e[32m\]\w\[\e[0m\]\n \$ '

# cow saying funny shit
fortune | cowsay
