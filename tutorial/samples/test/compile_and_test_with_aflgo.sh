#!/bin/bash
TARGET=$1
AFLGO=`pwd`/../../..
cd $AFLGO && make && cd -
TMP_DIR=$AFLGO/tutorial/samples/test/${TARGET}_temp
ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
LDFLAGS=-lpthread
SUBJECT=$AFLGO/tutorial/samples/test
DIR_IN=${SUBJECT}/${TARGET}_in
DIR_OUT=${SUBJECT}/${TARGET}_out
if [ ! -n "$1" ] ;then
	echo "Please provide the program name as the first argument. e.g 'entry' for entry.c in samples directory."
fi
TIME=2m
if [ "$TARGET" == "entry" ] ; then
	TIME=1m
elif [ "$TARGET" == "regex" ] ; then
	TIME=2m
elif [ "$TARGET" == "maze" ] ; then
	TIME=1m #shink early as a longer path has a shorter distance
fi

if [ "$2" != "-" ] ; then
	if [ ! -f ./${TARGET}.c ]; then
	    echo "We need ${TARGET}.c in current directory:$SUBJECT."
	    exit 1
	fi
        rm -rf $TMP_DIR # *.bc *.resolution.txt *.o
        #Prepare Target Info
	
	mkdir $TMP_DIR
	if [ "$TARGET" == "entry" ] ; then
		echo "entry.c:47"> $TMP_DIR/BBtargets.txt
	elif [ "$TARGET" == "regex" ] ; then
		echo "regex.c:88"> $TMP_DIR/BBtargets.txt
	elif [ "$TARGET" == "maze" ] ; then
		#specify the first line number of a basic block, the fuzzer cannot locate a basic block by a secord or following line number"
		echo -e "maze.c:108\nmaze.c:109"> $TMP_DIR/BBtargets.txt
	fi

	pushd $AFLGO
	#CC=clang CFLAGS="-fsanitize=address -fno-omit-frame-pointer" make clean all
	make
	cd $AFLGO/llvm_mode
	make #clean all
	popd
	CC=$AFLGO/afl-clang-fast 
	gcc ./${TARGET}.c -g3 -o ${TARGET}
        clang ${TARGET}.c -g3 -emit-llvm -S -c -o ${TARGET}.ll
	$CC $ADDITIONAL $LDFLAGS  ./${TARGET}.c -o ${TARGET}_profiled
        #set -v 
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
        
	$AFLGO/scripts/index_all_cfg_edges.py -t $TMP_DIR
        ./vis-dot.sh $TMP_DIR/dot-files
	
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
		#echo "ssssddddwwaawwddddssssddwww1"> $DIR_IN/words1
		#echo "ssssddddwwaawwddddsdd1"> $DIR_IN/words2 
		#echo "sddwddddssssddwww1"> $DIR_IN/words3 
		#echo "sddwddddsdd1"> $DIR_IN/words4 
		#good seed: 36s:wwaassdd,6min:ssswwaawwddddssssddwww
		#valid answer e.g. "ssssddddwwaawwddddssssddwwww" "ssssddddwwaawwddddsddwwdwww" "sddwddddsddwdw" "ssssddddwwaawwddddsddwdw"
	fi
	rm -rf $DIR_OUT
        
fi

ITER=20
if [ "$TARGET" == "maze" ] ; then
for((i=1;i<=$((ITER));i++));  
do
#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -x $SUBJECT/maze.dict -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
/usr/bin/time -a -o time.maze.txt $AFLGO/afl-fuzz -S ${TARGET}_$((i))_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -x $SUBJECT/maze.dict -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
mv $DIR_OUT/${TARGET}_$((i))_result  $DIR_OUT/../
done
mv $DIR_OUT/../${TARGET}_*_result  $DIR_OUT/
else
#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
/usr/bin/time -a -o time.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
fi


