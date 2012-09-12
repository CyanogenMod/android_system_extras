#!/system/bin/sh

# TODO: restructure this to keep bugreports entirely on internal storage

# Do not allow bugreports on user builds unless USB debugging
# is enabled.
if [ "x$(getprop ro.build.type)" = "xuser" -a \
     "x$(getprop init.svc.adbd)" != "xrunning" ]; then
  exit 0
fi

# Build emulated storage paths when appropriate
# See storage config details at http://source.android.com/tech/storage/
if [ -n "$EMULATED_STORAGE_SOURCE" ]; then
  writePath="$EMULATED_STORAGE_SOURCE/0"
  readPath="$EMULATED_STORAGE_TARGET/0"
else
  writePath="$EXTERNAL_STORAGE"
  readPath="$EXTERNAL_STORAGE"
fi

tmpPath="/data/local/tmp"
bugreportPath="bugreports"
screenshotPath="Pictures/Screenshots"

# Create directories if needed
if [ ! -e "$writePath/$bugreportPath" ]; then
  mkdir "$writePath/$bugreportPath"
fi
if [ ! -e "$writePath/$screenshotPath" ]; then
  mkdir "$writePath/$screenshotPath"
fi

timestamp=`date +'%Y-%m-%d-%H-%M-%S'`

# take screen shot
# we run this as a bg job in case screencap is stuck
/system/bin/screencap -p "$writePath/$screenshotPath/Screenshot_$timestamp.png" &

# run bugreport
/system/bin/dumpstate -o "$tmpPath/bugreport-$timestamp" $@

# copy finished bugreport into place for sending
cp "$tmpPath/bugreport-$timestamp.txt" "$writePath/$bugreportPath/bugreport-$timestamp.txt"
# clean up any remaining files
rm $tmpPath/bugreport*

# invoke send_bug to look up email accounts and fire intents
# make it convenient to send bugreport to oneself
/system/bin/send_bug "$readPath/$bugreportPath/bugreport-$timestamp.txt" "$readPath/$screenshotPath/Screenshot_$timestamp.png"
