#!/bin/bash

# Kernel configration options.
OPTIONS=" IPV6 IPV6_ROUTER_PREF IPV6_MULTIPLE_TABLES IPV6_ROUTE_INFO"
OPTIONS="$OPTIONS TUN IP_ADVANCED_ROUTER IP_MULTIPLE_TABLES"
OPTIONS="$OPTIONS NETFILTER NETFILTER_ADVANCED NETFILTER_XTABLES"
OPTIONS="$OPTIONS NETFILTER_XT_MARK NETFILTER_XT_TARGET_MARK"
OPTIONS="$OPTIONS IP_NF_IPTABLES IP_NF_MANGLE"
OPTIONS="$OPTIONS IP6_NF_IPTABLES IP6_NF_MANGLE"

# How many tap interfaces to create.
NUMTAPINTERFACES=2

# The root filesystem disk image we'll use.
ROOTFS=$(dirname $0)/net_test.rootfs

# Figure out which test to run.
if [ -z "$1" ]; then
  echo "Usage: $0 <test>" >&2
  exit 1
fi
test=$1

set -e

# Check if we need to uncompress the disk image.
# We use xz because it compresses better: to 42M vs 72M (gzip) / 62M (bzip2).
if [ $ROOTFS.xz -nt $ROOTFS ]; then
  echo "Uncompressing $ROOTFS.xz" >&2
  unxz --keep $ROOTFS.xz
fi


# Create NUMTAPINTERFACES tap interfaces on the host, and prepare UML command
# line params to use them. The interfaces are called <user>TAP0, <user>TAP1,
# ..., on the host, and eth0, eth1, ..., in the VM.
user=${USER:0:10}
tapinterfaces=
netconfig=
for id in $(seq 0 $(( NUMTAPINTERFACES - 1 )) ); do
  tap=${user}TAP$id
  tapinterfaces="$tapinterfaces $tap"
  mac=$(printf fe:fd:00:00:00:%02x $id)
  netconfig="$netconfig eth$id=tuntap,$tap,$mac"
done

for tap in $tapinterfaces; do
  if ! ip link list $tap > /dev/null; then
    echo "Creating tap interface $tap" >&2
    sudo tunctl -u $USER -t $tap
    sudo ip link set $tap up
  fi
done

# Exporting ARCH=um SUBARCH=x86_64 doesn't seem to work, as it "sometimes" (?)
# results in a 32-bit kernel.

# If there's no kernel config at all, create one or UML won't work.
[ -f .config ] || make defconfig ARCH=um SUBARCH=x86_64

# Enable the kernel config options listed in $OPTIONS.
cmdline=${OPTIONS// / -e }
./scripts/config $cmdline
make olddefconfig ARCH=um SUBARCH=x86_64

# Compile the kernel.
make -j12 linux ARCH=um SUBARCH=x86_64

# Get the absolute path to the test file that's being run.
dir=/host$(dirname $(readlink -f $0))

# Start the VM.
exec ./linux umid=net_test ubda=$(dirname $0)/net_test.rootfs \
    mem=512M init=/sbin/net_test.sh net_test=$dir/$test \
    $netconfig
