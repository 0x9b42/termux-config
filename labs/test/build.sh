MANIFEST=AndroidManifest.xml
ANDROID_JAR=~/android/sdk/platforms/android-33/android.jar
PACKAGE="$1"
APKOUT="$(echo $PACKAGE | sed 's,/,.,g')"

echo clean build files
rm build -fr

echo generate R.java
aapt package -f -m -J src -M $MANIFEST -S res -I $ANDROID_JAR

echo compile *.java
ecj -d build src/$PACKAGE/*.java

echo generate classes.dex
cd build
dx --dex --output=classes.dex $PACKAGE/*.class

echo generate apk
aapt package -m -F "$APKOUT.apk" -M ../$MANIFEST -S ../res -I $ANDROID_JAR

echo add classes.dex to apk
aapt add "$APKOUT.apk" classes.dex

echo align apk
zipalign -v 4 "$APKOUT.apk" "${APKOUT}_aligned.apk"

cd -
echo -e "\e[1;92mBUILT SUCCESSFULLY!\e[0m"
