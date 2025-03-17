M=AndroidManifest.xml
ANDROID_JAR=~/android/sdk/platforms/android-33/android.jar
PACKAGE=mob/demoapp


echo hapus build files dulu
rm -fr build

echo generate R.java
aapt package -f -m -J src -M $M -I $ANDROID_JAR


echo compile source *.java
ecj -d build src/$PACKAGE/*.java


echo build classes.dex dan lib
cd build
dx --dex --output=classes.dex $PACKAGE/*.class
cp -r ../lib . && cd lib/armeabi-v7a/
clang -shared libhello.c -o libtest.so
cd -

echo build apk
aapt package -m -F output.apk -M ../$M -S ../res \
  -I $ANDROID_JAR


echo masukin classes.dex dan lib ke apk
aapt add output.apk classes.dex
aapt add output.apk lib/armeabi-v7a/libtest.so

echo align dulu pake zipalign
zipalign -v 4 output.apk output_align.apk

echo keenam, done
echo DONEEEEEEEEE
