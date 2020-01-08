#!/bin/bash
pushd `pwd`
WORK=`pwd`
NAME=sqlite-2016-11-14
TEST_SUITE_DIR=$WORK/fuzzer-test-suite

if [ "$1" == "good" ];then
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-good
DOWNLOAD_DIR=$WORK/build_good_${NAME}
elif [ "$1" == "bad" ];then
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-origin
DOWNLOAD_DIR=$WORK/build_bad_${NAME}
elif [ "$1" != "-" ];then 
echo "INVALID 1st ARGUMENT:$1"
exit
fi
TARGET="target"

if [ ! -d $DOWNLOAD_DIR ]; then
mkdir $DOWNLOAD_DIR
fi 
cd $DOWNLOAD_DIR
#SUBJECT=$TEST_SUITE_DIR/libpng-1.2.56
SUBJECT=$DOWNLOAD_DIR
TMP_DIR=$SUBJECT/temp
SCRIPT_DIR=$TEST_SUITE_DIR/sqlite-2016-11-14
:<<!
if [ "$1" != "-" ] ; then
	#rm -rf $TMP_DIR	
	if [ ! -d $TMP_DIR ]; then
		mkdir $TMP_DIR
	fi
	echo -e "sqlite3.c:34987\nsqlite3.c:34994\nsqlite3.c:34995\nsqlite3.c:34996\nsqlite3.c:27407\nsqlite3.c:27408\nsqlite3.c:27409\nsqlite3.c:35105\n" >$TMP_DIR/BBtargets.txt
	
	ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
	SEC_FLAGS="-fsanitize=address,undefined -Wformat -Werror=format-security -Werror=array-bounds"
	export CC=$AFLGO/afl-clang-fast
	export CXX=$AFLGO/afl-clang-fast++

	export CFLAGS="-g3 $SEC_FLAGS $ADDITIONAL"
	export CXXFLAGS="-g3 $SEC_FLAGS $ADDITIONAL"
	export LDFLAGS="-lpthread"

	cd $SUBJECT
	
	#1st compile
	#$CC $CFLAGS -c $SCRIPT_DIR/sqlite3.c
	#$CC $CFLAGS -c $SCRIPT_DIR/ossfuzz.c
	#$CXX $CFLAGS $LDFLAGS -ldl -pthread sqlite3.o ossfuzz.o $TEST_SUITE_DIR/examples/example-hooks.cc  -o ${TARGET}_profiled
	
	# Clean up
	#cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
	#cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

	# Generate distance

	#$AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR ${TARGET}_profiled

	echo "Distance values:"
	head -n5 $TMP_DIR/distance.cfg.txt
	echo "..."
	tail -n5 $TMP_DIR/distance.cfg.txt
	
	export CFLAGS="$SEC_FLAGS -distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
	export CXXFLAGS="$SEC_FLAGS -distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"

	cd $SUBJECT

	#2nd compile
	export AFL_USE_ASAN=1
	$CC $CFLAGS -c $SCRIPT_DIR/sqlite3.c
	$CC $CFLAGS -c $SCRIPT_DIR/ossfuzz.c
	$CXX $CFLAGS $LDFLAGS -ldl -pthread sqlite3.o ossfuzz.o $TEST_SUITE_DIR/examples/example-hooks.cc  -o ${TARGET}_profiled
	$AFLGO/scripts/index_all_cfg_edges.py -t $TMP_DIR
	#$AFLGO/tutorial/samples/test/vis-dot.sh $TMP_DIR/dot-files
fi
!
cd $SUBJECT

TIME=100m
DIR_IN=$DOWNLOAD_DIR/in
DIR_IN="-"
DIR_OUT=$DOWNLOAD_DIR/out

if [ "$DIR_IN" != "-" -a ! -d $DIR_IN ]; then
	mkdir $DIR_IN
	cp $TEST_SUITE_DIR/sqlite-2016-11-14/crash* $DIR_IN
fi

TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-good.txt
if [[ $AFLGO == *good ]];then
	TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-good.txt
elif [[ $AFLGO == *origin ]];then
	TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-bad.txt
fi
if [ -f $TIME_RECORD_FILE ]; then
	rm $TIME_RECORD_FILE
fi

ITER=1
for((i=1;i<=$((ITER));i++));
do
if [ "$DIR_IN" != "-" -a -d $DIR_OUT ]; then
	rm -rf $DIR_OUT
fi

if [[ $AFLGO == *good ]];then
	#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR -x $SCRIPT_DIR/sql.dict $SUBJECT/${TARGET}_profiled @@
	/usr/bin/time -a -o $TIME_RECORD_FILE $AFLGO/afl-fuzz -m none -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR -x $SCRIPT_DIR/sql.dict $SUBJECT/${TARGET}_profiled @@
elif [[ $AFLGO == *origin ]];then
	#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -x $AFLGO/dictionaries/sql.dict $SUBJECT/${TARGET}_profiled @@
	/usr/bin/time -a -o $TIME_RECORD_FILE $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -x $SCRIPT_DIR/sql.dict $SUBJECT/${TARGET}_profiled @@
fi
done
popd
