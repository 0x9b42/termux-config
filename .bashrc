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
#fortune | cowsay

export OPTDIR=$HOME/opt

export     ANDROID_HOME=$OPTDIR/android/sdk
export ANDROID_SDK_ROOT=$OPTDIR/android/sdk
export ANDROID_NDK_ROOT=$OPTDIR/android/ndk
export      GRADLE_HOME=$OPTDIR/gradle
export        JAVA_HOME=$PREFIX/lib/jvm/java-17-openjdk
export _JAVA_OPTIONS='-Xmx512m'

export ANDROID_JAR=$ANDROID_HOME/platforms/android-33/android.jar
export AAPT2=$ANDROID_HOME/build-tools/34.0.4/aapt2

PATH="$PATH:~/.local/bin"
PATH="$PATH:$ANDROID_NDK_ROOT"
PATH="$PATH:$ANDROID_SDK_ROOT/platform-tools"
PATH="$PATH:$ANDROID_SDK_ROOT/build-tools/34.0.4"
PATH="$PATH:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin"
PATH="$PATH:$GRADLE_HOME/bin"
export PATH


python ~/.quiz_cards/quizzer.py
eval "$(starship init bash)"
source ~/.config/starship_completions.sh




