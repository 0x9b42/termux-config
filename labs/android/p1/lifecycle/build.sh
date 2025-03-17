#!/bin/bash

# Set error handling
set -e  # Exit if any command fails

# Clear old build files
echo "[*] Cleaning previous builds..."
rm -rf bin obj src/mob/lifecycle/R.java

# Step 1: Generate R.java (Resource Java file)
echo "[*] Generating R.java..."
aapt package -f -m -J src -S res -M AndroidManifest.xml -I $ANDROID_JAR 2>/dev/null

# Step 2: Compile Java source files to .class (Suppress deprecated warnings)
echo "[*] Compiling Java files..."
#javac -d obj -classpath $ANDROID_JAR $(find src -name "*.java") -Xlint:-options 2>/dev/null
ecj -d obj $(find src -name "*.java")

# Step 3: Convert .class files to DEX format
echo "[*] Converting to DEX format..."
mkdir -p bin
d8 --output bin --classpath $ANDROID_JAR $(find obj -name "*.class") 2>/dev/null

# Step 4: Package APK (without DEX yet)
echo "[*] Creating APK package..."
aapt package -f -S res -M AndroidManifest.xml -I $ANDROID_JAR -F bin/app.apk 2>/dev/null

# Step 5: Add DEX files to the APK
echo "[*] Adding DEX files to APK..."
cd bin
aapt add app.apk *.dex 2>/dev/null
cd ..

# Step 6: Align the APK for better performance
echo "[*] Aligning APK..."
zipalign -f 4 bin/app.apk bin/app_align.apk >/dev/null

# Step 7: Share APK (Uncomment if you need signing before sharing)
echo "[*] APK ready: bin/app_align.apk"
termux-share bin/app_align.apk
