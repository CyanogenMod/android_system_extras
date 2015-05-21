# Script to start a set of apps in order and then in each iteration
# switch the focus to each one. For each iteration, the time to start
# the app is reported as measured using atrace events and via am ThisTime.
# The output also reports if applications are restarted (eg, killed by
# LMK since previous iteration) or if there were any direct reclaim
# events.
#
# Variation: the "-T" option skips all of the atrace instramentation and
# attempts to start the apps as quickly as possible.
#
# Example 1: start all default apps. 2 iterations
#
# ./systemapps.sh -i 2
#
# Example 2: just start chrome, feedly, and the home screen in a loop
#
# ./systemapps.sh -L "chrome feedly home" -i 5
#
# Example 3: just start the default apps as quickly as possible
#
# ./systemapps.sh -T
#
# Other options are described below.
#
iterations=1
tracecategories="gfx view am input memreclaim"
totaltimetest=0
forcecoldstart=0

appList="gmail hangouts chrome youtube play home"

function processLocalOption {
	ret=0
	case "$1" in
	(-A) unset appList;;
	(-F) forcecoldstart=1;;
	(-L) appList=$2; shift; ret=1;;
	(-T) totaltimetest=1;;
	(*)
		echo "$0: unrecognized option: $1"
		echo; echo "Usage: $0 [options]"
		echo "-A : use all known applications"
		echo "-F : force cold-start for all apps"
		echo "-L applist : list of applications"
		echo "   default: $appList"
		echo "-T : total time to start all apps"
		echo "-g : generate activity strings"
		echo "-i iterations"
		echo "-n : keep trace files"
		echo "-o output file"
		echo "-s : stop on error"
		echo "-t trace categories"
		exit 1;;
	esac
	return $ret
}

CMDDIR=$(dirname $0 2>/dev/null)
CMDDIR=${CMDDIR:=.}
. $CMDDIR/defs.sh

tmpTraceOutBase=./tmptrace

if [ $user !=  "root" -a $totaltimetest -eq 0 ]; then
	handleError Must be root on device
	exit 1
fi
doKeyevent HOME

function computeStats {
	label=$1
	t=$2
	restart=$3
	reclaim=$4
	frames=$5
	janks=$6
	curMax=$(eval "echo \$${label}max")
	curMax=${curMax:=0}
	curMin=$(eval "echo \$${label}min")
	curMin=${curMin:=100000}
	curSum=$(eval "echo \$${label}sum")
	curSum=${curSum:=0}
	curRestart=$(eval "echo \$${label}restart")
	curRestart=${curRestart:=0}
	curReclaim=$(eval "echo \$${label}reclaim")
	curReclaim=${curReclaim:=0}
	curFrames=$(eval "echo \$${label}frames")
	curFrames=${curFrames:=0}
	curJanks=$(eval "echo \$${label}janks")
	curJanks=${curJanks:=0}
	if [ $curMax -lt $t ]; then
		eval "${label}max=$t"
	fi
	if [ $curMin -gt $t ]; then
		eval "${label}min=$t"
	fi
	((curSum=curSum+t))
	eval "${label}sum=$curSum"

	((curRestart=curRestart+${restart:=0}))
	eval "${label}restart=$curRestart"
	((curReclaim=curReclaim+${reclaim:=0}))
	eval "${label}reclaim=$curReclaim"
	((curFrames=curFrames+${frames:=0}))
	eval "${label}frames=$curFrames"
	((curJanks=curJanks+${janks:=0}))
	eval "${label}janks=$curJanks"
}
function getStats {
	label=$1
	echo $(eval "echo \$${label}max") $(eval "echo \$${label}min") $(eval "echo \$${label}sum") \
		$(eval "echo \$${label}restart") $(eval "echo \$${label}reclaim") \
		$(eval "echo \$${label}frames") $(eval "echo \$${label}janks")
}

cur=1
totaltime=0
startTimestamp=$(date +"%s %N")

while [ $cur -le $iterations ]
do
	if [ $iterations -gt 1 ]; then
		echo =========================================
		echo Iteration $cur of $iterations
		echo =========================================
	fi
	if [ $iterations -gt 1 -o $cur -eq 1 ]; then
		if [ $totaltimetest -eq 0 ]; then
			printf "%-6s    %7s(ms)  %6s(ms) %s %s %s %s\n" App  Time AmTime Restart DirReclaim JankyFrames
		fi
	fi

	appnum=-1
	for app in $appList
	do
		vout Starting $app...
		((appnum=appnum+1))
		loopTimestamp=$(date +"%s %N")
		if [ $totaltimetest -gt 0 ]; then
			# no instramentation, just cycle through the apps
			if [ $appnum -eq 0 ]; then
				printf "%-8s %5s(ms) %3s(ms)\n" App Start Iter
			fi
			if [ $forcecoldstart -eq 0 ]; then
				t=$(startActivity $app)
			else
				t=$(forceStartActivity $app)
			fi
			loopEndTimestamp=$(date +"%s %N")
			diffTime=$(computeTimeDiff $loopTimestamp $loopEndTimestamp)
			# Note: "%d" doesn't work right if run on device
			printf "%-10s %5.0f   %5.0f\n" $app $t $diffTime
			((totaltime=totaltime+t))
			continue
		fi
		tmpTraceOut="$tmpTraceOutBase-$app.out"
		>$tmpTraceOut
		startInstramentation
		resetJankyFrames $(getPackageName $app)
		t=$(startActivity $app)
		# let app finish drawing before checking janks
		sleep 3
		set -- $(getJankyFrames $(getPackageName $app))
		frames=$1
		janks=$2
		((jankPct=100*janks/frames))
		stopAndDumpInstramentation $tmpTraceOut
		actName=$(getActivityName $app)
		stime=$(getStartTime $actName $tmpTraceOut)
		relaunch=$?
		etime=$(getEndTime $actName $tmpTraceOut)
		((tdiff=$etime-$stime))
		if [ $etime -eq 0 -o $stime -eq 0 ]; then
			handleError $app : could not compute start time stime=$stime  etime=$etime
			# use AmTime so statistics make sense
			tdiff=$t
		fi
		checkForDirectReclaim $actName $tmpTraceOut
		directReclaim=$?

		printf "%-12s %5d     %5d     %5d    %5d    %5d(%d%%)\n" "$app" "$tdiff" "$t" "$relaunch" "$directReclaim" "$janks" "$jankPct"
		computeStats "$app" "$tdiff" "$relaunch" "$directReclaim" "$frames" "$janks"

		if [ $savetmpfiles -eq 0 ]; then
			rm -f $tmpTraceOut
		fi
	done
	((cur=cur+1))
done
endTimestamp=$(date +"%s %N")
diffTime=$(computeTimeDiff $startTimestamp $endTimestamp)
if [ $totaltimetest -gt 0 ]; then
	printf "%-10s %5.0f   %5.0f\n" TOTAL $totaltime $diffTime
fi

if [ $iterations -gt 1 -a $totaltimetest -eq 0 ]; then
	echo
	echo =========================================
	printf "Stats after $iterations iterations:\n"
	echo =========================================
	printf "%-6s    %7s(ms) %6s(ms) %6s(ms)    %s    %s %s %s\n" App Max Ave Min Restart DirReclaim JankyFrames
	for app in $appList
	do
		set -- $(getStats $app)
		sum=$3
		((ave=sum/iterations))
		frames=$6
		janks=$7
		((jankPct=100*janks/frames))
		printf "%-12s %5d      %5d      %5d      %5d      %5d     %5d(%d%%)\n" $app $1 $ave $2 $4 $5 $janks $jankPct
	done
fi
