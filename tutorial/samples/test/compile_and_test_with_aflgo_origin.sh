#!/bin/bash
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-origin
AFLGO_GOOD=/home/yangke/Program/AFL/aflgo/bak/aflgo-good
export TMP_DIR=$AFLGO_GOOD/tutorial/samples/test/temp
export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
export LDFLAGS=-lpthread
export SUBJECT=$AFLGO_GOOD/tutorial/samples/test
if [ ! -n "$1" ] ;then
	echo "Please provide the program name as the first argument. e.g 'entry' for entry.c in samples directory."
fi
TARGET=$1
if [ "$2" != "-" ] ; then
	if [ ! -f ./${TARGET}.c ]; then
	    exit 1
	fi
        #rm -rf ./temp *.bc *.resolution.txt *.o
	mkdir ./temp
	if [ "$TARGET" == "entry" ] ; then
		echo "entry.c:47"> ./temp/BBtargets.txt
	elif [ "$TARGET" == "regex" ] ; then
		echo "regex.c:88"> ./temp/BBtargets.txt
	elif [ "$TARGET" == "maze" ] ; then
		echo "maze.c:109"> ./temp/BBtargets.txt
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
	$CC $ADDITIONAL $LDFLAGS  ./${TARGET}.c -o ${TARGET}_profiled
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

	$CC $CFLAGS  ./${TARGET}.c -o ${TARGET}_profiled

	$AFLGO/scripts/index_all_cfg_edges.py -d $TMP_DIR/dot-files
        ./vis-dot.sh

	# Construct seed corpus
	if [ ! -d ./in ] ;then
	    mkdir ./in
	else
	    rm ./in/*
	fi
        if [ "$TARGET" == "entry" ] ; then
		echo "whoamiwhoamiwhoami"> ./in/words #valid answer e.g. "_ _ _ _bai"
	elif [ "$TARGET" == "regex" ] ; then
		#echo "*a.^b\$c"> ./in/words #valid answer e.g. ".*"
                echo "abc"> ./in/words 
	elif [ "$TARGET" == "maze" ] ; then
		echo "wwaassdd"> ./in/words #good seed: 36s:wwaassdd,6min:ssswwaawwddddssssddwww
                #valid answer e.g. "ssssddddwwaawwddddssssddwwww" "ssssddddwwaawwddddsddwwdwww" "sddwddddsddwdw" "ssssddddwwaawwddddsddwdw"
	fi
	rm -rf ./out
fi
#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 2m -i in -o out $SUBJECT/${TARGET}_profiled @@
/usr/bin/time -a -o time.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 1m -i in -o out  $SUBJECT/${TARGET}_profiled @@
