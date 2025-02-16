# unlimited history
HISTSIZE=
HISTFILESIZE=

# unique command history
HISTCONTROL="erasedups:ignoreboth"

alya=(
    ~/.bash_aliases
    ~/.local/tools/vidutils.sh
)
for i in ${alya[@]}
do
    [ -f $i ] && . $i
done
unset alya

export PATH

PS1="\e[32m\w\e[0m\n \$ "

# cow saying funny shit
fortune | cowsay

export ANDROID_HOME="$HOME/android/sdk"
export ANDROID_SDK_ROOT="$HOME/android/sdk"
export ANDROID_NDK_ROOT="$HOME/android/ndk"
export JAVA_HOME="$PREFIX/lib/jvm/java-17-openjdk"
export _JAVA_OPTIONS="-Xmx512m"

PATH="~/.local/bin:$PATH"
PATH="$PATH:$ANDROID_SDK_ROOT/platform-tools"
PATH="$PATH:$ANDROID_SDK_ROOT/build-tools/34.0.4"
PATH="$PATH:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin"
PATH="$PATH:$HOME/.gradle/bin"
export PATH

ANDROID_JAR="$ANDROID_HOME/platforms/android-33/android.jar"
export ANDROID_JAR

#alias whoami='echo root'
#alias su='HOME="/" PS1=":\w # "'
#alias rm='/data/data/com.termux/files/usr/bin/su -c sleep 77'
#alias ls='sudo ls --color=never'
