#!/bin/bash
#
# To call this script, make sure mksquashfs is somewhere in PATH

function usage() {
cat<<EOT
Usage:
${0##*/} SRC_DIR OUTPUT_FILE [-m MOUNT_POINT] [-c FILE_CONTEXTS] [-b BLOCK_SIZE]
EOT
}

echo "in mksquashfsimage.sh PATH=$PATH"

if [ $# -lt 2 ]; then
    usage
    exit 1
fi

SRC_DIR=$1
if [ ! -d $SRC_DIR ]; then
  echo "Can not find directory $SRC_DIR!"
  exit 2
fi
OUTPUT_FILE=$2
shift; shift

MOUNT_POINT=
if [[ "$1" == "-m" ]]; then
    MOUNT_POINT=$2
    shift; shift
fi

FILE_CONTEXTS=
if [[ "$1" == "-c" ]]; then
    FILE_CONTEXTS=$2
    shift; shift
fi

BLOCK_SIZE=131072
if [[ "$1" == "-b" ]]; then
    BLOCK_SIZE=$2
    shift; shift
fi

OPT=""
if [ -n "$MOUNT_POINT" ]; then
  OPT="$OPT -mount-point $MOUNT_POINT"
fi
if [ -n "$FILE_CONTEXTS" ]; then
  OPT="$OPT -context-file $FILE_CONTEXTS"
fi
if [ -n "$BLOCK_SIZE" ]; then
  OPT="$OPT -b $BLOCK_SIZE"
fi

MAKE_SQUASHFS_CMD="mksquashfs $SRC_DIR $OUTPUT_FILE -no-progress -comp lz4 -Xhc -no-exports -noappend -no-recovery -android-fs-config $OPT"
echo $MAKE_SQUASHFS_CMD
$MAKE_SQUASHFS_CMD
if [ $? -ne 0 ]; then
    exit 4
fi
