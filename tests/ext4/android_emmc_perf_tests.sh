#!/bin/bash

PERF="rand_emmc_perf"

if [ ! -r "$PERF" ]
then
  echo "Cannot read $PERF test binary"
fi

if [ ! -r "$PERF_OSYNC" ]
then
  echo "Cannot read $PERF_OSYNC test binary"
fi

if ! adb shell true >/dev/null 2>&1
then
  echo "No device detected over adb"
fi

HARDWARE=`adb shell getprop ro.hardware | tr -d "\r"`

case "$HARDWARE" in
  tuna | steelhead)
    CPUFREQ="/sys/devices/system/cpu/cpu0/cpufreq"
    CACHE="/dev/block/platform/omap/omap_hsmmc.0/by-name/cache"
    ;;

  stingray | wingray)
    CPUFREQ="/sys/devices/system/cpu/cpu0/cpufreq"
    CACHE="/dev/block/platform/sdhci-tegra.3/by-name/cache"
    ;;

  herring)
    echo "This test will wipe the userdata partition on $HARDWARE devices."
    read -p "Do you want to proceed? " ANSWER

    if [ "$ANSWER" != "yes" ]
    then
      echo "aborting test"
      exit 1
    fi

    CPUFREQ="/sys/devices/system/cpu/cpu0/cpufreq"
    CACHE="/dev/block/platform/s3c-sdhci.0/by-name/userdata"
    ;;

  grouper)
    CPUFREQ="/sys/devices/system/cpu/cpu0/cpufreq"
    CACHE="/dev/block/platform/sdhci-tegra.3/by-name/CAC"
    ;;

  *)
    echo "Unknown hardware $HARDWARE.  Exiting."
    exit 1
esac

# prepare the device
adb root
adb wait-for-device
adb push "$PERF" /dev
adb push "$PERF_OSYNC" /dev
adb shell stop
adb shell stop sdcard
adb shell stop ril-daemon
adb shell stop media
adb shell stop drm
adb shell stop keystore
adb shell stop tf_daemon
adb shell stop bluetoothd
adb shell stop hciattach
adb shell umount /sdcard >/dev/null 2>&1
adb shell umount /data >/dev/null 2>&1
adb shell umount /cache >/dev/null 2>&1
# Add more services here that other devices need to stop.
# So far, this list is sufficient for:
#   Prime

# At this point, the device is quiescent, need to crank up the cpu speed,
# then run tests
adb shell "cat $CPUFREQ/cpuinfo_max_freq > $CPUFREQ/scaling_max_freq"
adb shell "cat $CPUFREQ/cpuinfo_max_freq > $CPUFREQ/scaling_min_freq"

# Start the tests

# Sequential read test
for I in 1 2 3
do
  echo "Sequential read test $I"
  adb shell dd if="$CACHE" of=/dev/null bs=1048576 count=200
done

# Sequential write test
for I in 1 2 3
do
  echo "Sequential write test $I"
  adb shell dd if=/dev/zero of="$CACHE" bs=1048576 count=200
done

# Random read test
for I in 1 2 3
do
  echo "Random read test $I"
  adb shell /dev/"$PERF" -r 100 "$CACHE"
done

# Random write test
for I in 1 2 3
do
  echo "Random write test $I"
  adb shell /dev/"$PERF" -w 100 "$CACHE"
done

# Random write test with O_SYNC
for I in 1 2 3
do
  echo "Random write with o_sync test $I"
  adb shell /dev/"$PERF" -w 100 -o "$CACHE"
done

# Make a new empty /cache filesystem
adb shell make_ext4fs "$CACHE"

