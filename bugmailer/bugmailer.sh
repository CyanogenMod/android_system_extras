#!/system/bin/sh

timestamp=`date +'%Y-%m-%d-%H-%M-%S'`
storagePath="$EXTERNAL_STORAGE/bugreports"
bugreport=$storagePath/bugreport-$timestamp
buildDesc="`/system/bin/getprop ro.build.description`
(Sent from BugMailer)"

# run bugreport
/system/bin/dumpstate -o $bugreport $@


# make files readable
chown root.sdcard_rw $bugreport.txt

# send intent to mail it
/system/bin/am start -a android.intent.action.SEND \
    -t "application/octet-stream" \
    -e "subject" "bugreport-$timestamp" \
    -e "body" "$buildDesc" \
    --eu "android.intent.extra.STREAM" "file://$bugreport.txt"
