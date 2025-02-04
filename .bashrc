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

PS1="\e[32m\w\e[0m\n \$ "

# cow saying funny shit
fortune | cowsay

export ANDROID_USER_HOME="$HOME/android"
export ANDROID_HOME="$HOME/android/sdk"
export ANDROID_SDK_ROOT="$HOME/android/sdk"
export ANDROID_NDK_HOME="$HOME/android/ndk"
export JAVA_HOME="$PREFIX/lib/jvm/java-17-openjdk"
export CLASSPATH="$ANDROID_HOME/android/sdk/platforms/android-33/android.jar"
export GRADLE_USER_HOME="$HOME/.gradle"
export _JAVA_OPTIONS="-Xmx512m"


PATH="~/.local/bin:$PATH"
PATH="$PATH:$ANDROID_HOME/platform-tools"
PATH="$PATH:$ANDROID_HOME/build-tools/34.0.4"
PATH="$PATH:$ANDROID_HOME/cmdline-tools/latest/bin"
PATH="$PATH:$ANDROID_NDK_HOME"
PATH="$PATH:$HOME/.gradle/bin"
export PATH
