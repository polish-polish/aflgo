#!/bin/bash
TARGET=$1
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-origin
AFLGO_GOOD=/home/yangke/Program/AFL/aflgo/bak/aflgo-good
TMP_DIR=$AFLGO_GOOD/tutorial/samples/test/${TARGET}_origin_temp
ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
LDFLAGS=-lpthread
SUBJECT=$AFLGO_GOOD/tutorial/samples/test
DIR_IN=${SUBJECT}/${TARGET}_origin_in
DIR_OUT=${SUBJECT}/${TARGET}_origin_out
if [ ! -n "$1" ] ;then
	echo "Please provide the program name as the first argument. e.g 'entry' for entry.c in samples directory."
fi
TIME=2m
if [ "$TARGET" == "entry" ] ; then
	TIME=1m
elif [ "$TARGET" == "regex" ] ; then
	TIME=2m
elif [ "$TARGET" == "maze" ] ; then
	TIME=1m
fi
if [ "$2" != "-" ] ; then
	if [ ! -f ./${TARGET}.c ]; then
	    exit 1
	fi
        rm -rf $TMP_DIR
	#rm *.bc *.resolution.txt *.o
	mkdir $TMP_DIR
	if [ "$TARGET" == "entry" ] ; then
		echo "entry.c:47"> $TMP_DIR/BBtargets.txt
	elif [ "$TARGET" == "regex" ] ; then
		echo "regex.c:88"> $TMP_DIR/BBtargets.txt
	elif [ "$TARGET" == "maze" ] ; then
		echo -e "maze.c:108\nmaze.c:109"> $TMP_DIR/BBtargets.txt
	fi
	pushd $AFLGO
	#make clean all
	make
	cd $AFLGO/llvm_mode
	#make clean all
	make
	popd
	CC=$AFLGO/afl-clang-fast
	gcc ./${TARGET}.c -o ${TARGET}
        clang ${TARGET}.c -emit-llvm -S -c -o ${TARGET}.ll
	$CC $ADDITIONAL $LDFLAGS  ./${TARGET}.c -o ${TARGET}_profiled_origin
        set -v 
	# Clean up
	cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
	cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt


	# Generate distance 
	$AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR ${TARGET}

	echo "Distance values:"
	head -n5 $TMP_DIR/distance.cfg.txt
	echo "..."
	tail -n5 $TMP_DIR/distance.cfg.txt


	CFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
	CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"

	$CC $CFLAGS  ./${TARGET}.c -o ${TARGET}_profiled_origin

	# Construct seed corpus
	if [ ! -d $DIR_IN ] ;then
	    mkdir $DIR_IN
	else
	    rm $DIR_IN/*
	fi
	if [ "$TARGET" == "entry" ] ; then
		echo "whoamiwhoamiwhoami"> $DIR_IN/words 
		#valid answer e.g. "_ _ _ _bai"
	elif [ "$TARGET" == "regex" ] ; then
		echo "abc"> $DIR_IN/words
		#echo "*a.^b\$c"> $DIR_IN/words
		#valid answer e.g. ".*"
	elif [ "$TARGET" == "maze" ] ; then
		echo ""> $DIR_IN/words                 
		#echo "wwaassdd"> $DIR_IN/words 
		#good seed: 36s:wwaassdd,6min:ssswwaawwddddssssddwww
		#valid answer e.g. "ssssddddwwaawwddddssssddwwww" "ssssddddwwaawwddddsddwwdwww" "sddwddddsddwdw" "ssssddddwwaawwddddsddwdw"
	fi
	rm -rf $DIR_OUT
fi
#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT $SUBJECT/${TARGET}_profiled @@

ITER=1
if [ "$TARGET" == "maze" ] ; then
for((i=1;i<=$((ITER));i++));  
do
echo "/usr/bin/time -a -o time.maze.origin.txt $AFLGO/afl-fuzz -S ${TARGET}_$((i))_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -x $SUBJECT/maze.dict $SUBJECT/${TARGET}_profiled_origin @@"
/usr/bin/time -a -o time.maze.origin.txt $AFLGO/afl-fuzz -S ${TARGET}_$((i))_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -x $SUBJECT/maze.dict $SUBJECT/${TARGET}_profiled_origin @@
mv $DIR_OUT/${TARGET}_$((i))_result  $DIR_OUT/../../
done
mv $DIR_OUT/../../${TARGET}_*_result  $DIR_OUT/
else
/usr/bin/time -a -o time.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT  $SUBJECT/${TARGET}_profiled @@
fi
