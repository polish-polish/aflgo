#!/bin/bash
pushd `pwd`
WORK=`pwd`
NAME=libjpeg-turbo-07-1017
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

TARGET=jdmarker 

if [ ! -d $DOWNLOAD_DIR ]; then
mkdir $DOWNLOAD_DIR
fi 
cd $DOWNLOAD_DIR

SUBJECT=$DOWNLOAD_DIR
TMP_DIR=$SUBJECT/temp
SCRIPT_DIR=$TEST_SUITE_DIR/libjpeg-turbo-07-2017
:<<!
if [ "$1" != "-" ] ; then
	if [ -d $TMP_DIR ]; then
		rm -rf $TMP_DIR
	fi
	mkdir $TMP_DIR
	#echo -e "jdmarker.c:608\njdmarker.c:610\njdmarker.c:644\njdmarker.c:654\njdmarker.c:658\njdmarker.c:659\njdmarker.c:660" >$TMP_DIR/BBtargets.txt 

	[ ! -e libjpeg-turbo ] && git clone https://github.com/libjpeg-turbo/libjpeg-turbo.git && cd libjpeg-turbo && git checkout b0971e47d && cd ..
	[ ! -d ./BUILD ] && cp -R libjpeg-turbo BUILD

	rm -rf ./BUILD
	cp -R libjpeg-turbo BUILD

	#setup targets# jdmarker.c:659
	if [ "`sed -n 659p  BUILD/jdmarker.c`" != "abort();" ] ;then
		sed "658 aabort();" -i BUILD/jdmarker.c
	fi
	echo -e "jdmarker.c:658\njdmarker.c:659" >$TMP_DIR/BBtargets.txt

	
	ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"

	export CC=$AFLGO/afl-clang-fast
	export CXX=$AFLGO/afl-clang-fast++

	export CFLAGS="-g3 $ADDITIONAL"
	export CXXFLAGS="-g3 $ADDITIONAL"
	export LDFLAGS="-lpthread"

	#1st compile
	cd $DOWNLOAD_DIR/BUILD/
	autoreconf -fiv
	[ ! -e ./Makefile ] && ./configure --disable-shared
	[ -e ./.libs/libturbojpeg.a ] && make clean
	cd simd && make && cd .. && make libturbojpeg.la
	cd $SUBJECT
	$CXX $CXXFLAGS $LDFLAGS -std=c++11 -v $SCRIPT_DIR/libjpeg_turbo_fuzzer.cc $TEST_SUITE_DIR/examples/example-hooks.cc -I BUILD BUILD/.libs/libturbojpeg.a  -o ${TARGET}_profiled

	# Clean up
	cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
	cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

	# Generate distance

	$AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR ${TARGET}_profiled
	#cat $TMP_DIR/distance.callgraph.txt | sort | uniq > $TMP_DIR/distance.callgraph2.txt && mv $TMP_DIR/distance.callgraph2.txt $TMP_DIR/distance.callgraph.txt

	echo "Distance values:"
	head -n5 $TMP_DIR/distance.cfg.txt
	echo "..."
	tail -n5 $TMP_DIR/distance.cfg.txt

	
	export CFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
	export CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"

	#2nd compile
	cd $DOWNLOAD_DIR/BUILD/	
	./configure --disable-shared
	if [ -d $TMP_DIR/rid_bbname_pairs.txt ];then
		rm $TMP_DIR/rid_bbname_pairs.txt
	fi
	make clean
	cd simd && make && cd .. && make libturbojpeg.la

	cd $SUBJECT
	$CXX $CXXFLAGS $LDFLAGS -std=c++11 -v $SCRIPT_DIR/libjpeg_turbo_fuzzer.cc $TEST_SUITE_DIR/examples/example-hooks.cc -I BUILD BUILD/.libs/libturbojpeg.a  -o ${TARGET}_profiled
	if [[ $AFLGO == *good ]];then
		$AFLGO/scripts/index_all_cfg_edges.py -d $TMP_DIR/dot-files
		#$AFLGO/tutorial/samples/test/vis-dot.sh $TMP_DIR/dot-files
	fi
fi
!
cd $SUBJECT

TIME=1m
DIR_IN=$DOWNLOAD_DIR/in
DIR_OUT=$DOWNLOAD_DIR/out
if [ "$DIR_IN" != "-" -a ! -d $DIR_IN ]; then
	mkdir $DIR_IN
	cp $TEST_SUITE_DIR/libjpeg-turbo-07-2017/seeds/seed.jpg $DIR_IN
fi
TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-good.txt
if [[ $AFLGO == *good ]];then
	TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-good.txt
elif [[ $AFLGO == *origin ]];then
	TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-bad.txt
fi
if [ -f $TIME_RECORD_FILE ];then
	rm $TIME_RECORD_FILE
fi

ITER=10
for((i=1;i<=$((ITER));i++));  
do
if [ -d $DIR_OUT ]; then
	rm -rf $DIR_OUT
fi
if [[ $AFLGO == *good ]];then
	#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR -x $AFLGO/dictionaries/jpeg.dict $SUBJECT/${TARGET}_profiled @@
	/usr/bin/time -a -o $TIME_RECORD_FILE $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR -x $AFLGO/dictionaries/jpeg.dict $SUBJECT/${TARGET}_profiled @@
elif [[ $AFLGO == *origin ]];then
	#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -x $AFLGO/dictionaries/jpeg.dict $SUBJECT/${TARGET}_profiled @@
	/usr/bin/time -a -o $TIME_RECORD_FILE $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -x $AFLGO/dictionaries/jpeg.dict $SUBJECT/${TARGET}_profiled @@
fi
done
popd
