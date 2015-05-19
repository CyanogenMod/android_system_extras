#
# Script to start a set of apps, switch to recents and fling it back and forth.
# For each iteration, Total frames and janky frames are reported.
#
# Options are described below.
#
# Works for volantis, shamu, and hammerhead. Can be pushed and executed on
# the device.
#
iterations=10
startapps=1
capturesystrace=0

function processLocalOption {
	ret=0
	case "$1" in
	(-N) startapps=0;;
	(-A) unset appList;;
	(-L) appList=$2; shift; ret=1;;
	(-T) capturesystrace=1;;
	(*)
		echo "$0: unrecognized option: $1"
		echo; echo "Usage: $0 [options]"
		echo "-A : use all known applications"
		echo "-L applist : list of applications"
		echo "   default: $appList"
		echo "-N : no app startups, just fling"
		echo "-g : generate activity strings"
		echo "-i iterations"
		echo "-T : capture systrace on each iteration"
		exit 1;;
	esac
	return $ret
}

CMDDIR=$(dirname $0 2>/dev/null)
CMDDIR=${CMDDIR:=.}
. $CMDDIR/defs.sh

case $DEVICE in
(shamu|hammerhead)
	flingtime=300
	downCount=2
	upCount=6
	UP="70 400 70 100 $flingtime"
	DOWN="70 100 70 400 $flingtime";;
(volantis)
	flingtime=400
	downCount=5
	upCount=6
	UP="70 400 70 70 $flingtime"
	DOWN="70 70 70 400 $flingtime";;
(*)
	echo "Error: No display information available for $DEVICE"
	exit 1;;
esac

doKeyevent HOME
if [ $startapps -gt 0 ]; then

	# start a bunch of apps
	for app in $appList
	do
		echo Starting $app ...
		t=$(startActivity $app)
	done
fi

cur=1

set -- $(getJankyFrames)
totalFrames=$1
jankyFrames=$2
frameSum=0
jankSum=0

if [ ${totalFrames:=0} -eq 0 ]; then
#echo Error: could not read frame info with \"dumpsys graphicsstats\"
	echo Error: could not read frame info with \"dumpsys gfxinfo\"
	exit 1
fi

function swipe {
	count=0
	while [ $count -lt $2 ]
	do
		doSwipe $1
		((count=count+1))
	done
}

echo Fling recents...
doKeyevent APP_SWITCH

while [ $cur -le $iterations ]
do
	if [ $capturesystrace -gt 0 ]; then
		${ADB}atrace --async_start -z -c -b 16000 freq gfx view idle sched
	fi
	swipe "$DOWN" $downCount
	sleep 1
	swipe "$UP" $upCount
	sleep 1
	swipe "$DOWN" $downCount
	sleep 1
	swipe "$UP" $upCount
	sleep 1
	if [ $capturesystrace -gt 0 ]; then
		${ADB}atrace --async_dump -z -c -b 16000 freq gfx view idle sched > trace.${cur}.out
	fi

	set -- $(getJankyFrames)
	newTotalFrames=$1
	newJankyFrames=$2
	((totalDiff=newTotalFrames-totalFrames))
	((frameSum=frameSum+totalDiff))
	((jankyDiff=newJankyFrames-jankyFrames))
	((jankSum=jankSum+jankyDiff))
	if [ "$totalDiff" -eq 0 ]; then
		echo Error: no frames detected. Is the display off?
		exit 1
	fi
	((jankPct=jankyDiff*100/totalDiff))
	totalFrames=$newTotalFrames
	jankyFrames=$newJankyFrames

	echo Frames: $totalDiff Janks: $jankyDiff \(${jankPct}%\)
	((cur=cur+1))
done
doKeyevent HOME
((aveJankPct=jankSum*100/frameSum))
echo AVE: Frames: $frameSum Janks: $jankSum \(${aveJankPct}%\)
