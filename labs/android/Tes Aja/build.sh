#!/bin/bash
_i() {
  echo -e "[*][34;1m $@[0m"
}
_d() {
  echo -e "[√][32;1m $@[0m"
}
set -e
_i prep ...
rm -fr output
mkdir -p output
_i running aapt ...
aapt package -f -m -J java -S res -M AndroidManifest.xml -I /data/data/com.termux/files/home/android/sdk/platforms/android-33/android.jar -F output/app.apk
_i compiling java files ...
ecj -d output $(find java -name *.java)
_i packaging APK ...
cd output
dx --dex --output=classes.dex $(find mob -name *.class)
zip -r app.apk classes.dex
_i optimizing APK ...
zipalign -v 4 app.apk unsigned.apk
rm app.apk
_d built successfully: output/unsigned.apk
_i sign the apk first to install
termux-share unsigned.apk
