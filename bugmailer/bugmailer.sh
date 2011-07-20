#!/system/bin/sh

timestamp=`date +'%Y-%m-%d-%H-%M-%S'`
storagePath="$EXTERNAL_STORAGE/bugreports"
bugreport=$storagePath/bugreport-$timestamp

# run bugreport
/system/bin/dumpstate -o $bugreport $@


# make files readable
chown root.sdcard_rw $bugreport.txt

# invoke send_bug to look up email accounts and fire intents
# make it convenient to send bugreport to oneself
/system/bin/send_bug $bugreport.txt
