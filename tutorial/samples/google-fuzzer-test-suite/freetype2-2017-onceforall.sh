#!/bin/bash
pushd `pwd`
WORK=`pwd`
NAME=freetype2-2017
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
TARGET=ttgload
if [ ! -d $DOWNLOAD_DIR ]; then
mkdir $DOWNLOAD_DIR
fi 
cd $DOWNLOAD_DIR

SUBJECT=$DOWNLOAD_DIR
TMP_DIR=$SUBJECT/temp
:<<!
if [ "$1" != "-" ] ; then
	if [ -d $TMP_DIR ]; then
		rm -rf $TMP_DIR
	fi
	mkdir $TMP_DIR

	[ ! -d freetype2 ] && git clone git://git.sv.nongnu.org/freetype/freetype2.git && cd freetype2 && git checkout cd02d359a6d0455e9d16b87bf9665961c4699538 && cd ..
	[ ! -d BUILD ] && cp -R freetype2 BUILD
	rm -rf ./BUILD
	cp -R freetype2 BUILD

	#setup targets
	if [ "`sed -n 1711p  BUILD/src/truetype/ttgload.c`" != "{abort();" ] ;then
		sed "1710 a{abort();" -i BUILD/src/truetype/ttgload.c
		sed "1712 a}" -i BUILD/src/truetype/ttgload.c
	fi
	echo -e "ttgload.c:1710\nttgload.c:1711" >$TMP_DIR/BBtargets.txt

	cd $DOWNLOAD_DIR/BUILD/
	ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"

	export CC=$AFLGO/afl-clang-fast
	export CXX=$AFLGO/afl-clang-fast++

	export CFLAGS="-g3 $ADDITIONAL"
	export CXXFLAGS="-g3 $ADDITIONAL"
	export LDFLAGS="-lpthread"

	#1st compile
	./autogen.sh
	./configure  --disable-shared --with-harfbuzz=no --with-bzip2=no --with-png=no
	make
	cd $SUBJECT
	$CXX $CXXFLAGS -std=c++11 -I BUILD/include -I BUILD/ BUILD/src/tools/ftfuzzer/ftfuzzer.cc $TEST_SUITE_DIR/examples/example-hooks.cc BUILD/objs/.libs/libfreetype.a -lpng -larchive -lbz2 -lz -o ${TARGET}_profiled

	# Clean up
	cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
	cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

	# Generate distance

	$AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR ${TARGET}_profiled

	echo "Distance values:"
	head -n5 $TMP_DIR/distance.cfg.txt
	echo "..."
	tail -n5 $TMP_DIR/distance.cfg.txt

	CFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
	CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"

	#2nd compile
	cd $DOWNLOAD_DIR/BUILD/	
	make clean && ./configure --disable-shared --with-harfbuzz=no --with-bzip2=no --with-png=no   && make
	cd $SUBJECT
	$CXX $CXXFLAGS -std=c++11 -I BUILD/include -I BUILD/ BUILD/src/tools/ftfuzzer/ftfuzzer.cc $TEST_SUITE_DIR/examples/example-hooks.cc BUILD/objs/.libs/libfreetype.a -lpng -larchive -lbz2 -lz -o ${TARGET}_profiled
	if [[ $AFLGO == *good ]];then
		$AFLGO/scripts/index_all_cfg_edges.py -t $TMP_DIR
		#$AFLGO/tutorial/samples/test/vis-dot.sh $TMP_DIR/dot-files
	fi
fi
!

TIME=40m
DIR_IN=$DOWNLOAD_DIR/in
DIR_OUT=$DOWNLOAD_DIR/out
#rm -rf $DIR_IN
if [ "$DIR_IN" != "-" -a ! -d $DIR_IN ]; then
  mkdir $DIR_IN
  git clone https://github.com/unicode-org/text-rendering-tests.git TRT
  # TRT/fonts is the full seed folder, but they're too big
  cp TRT/fonts/TestKERNOne.otf $DIR_IN/
  cp TRT/fonts/TestGLYFOne.ttf $DIR_IN/
  rm -fr TRT
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
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/
ITER=10
for((i=1;i<=$((ITER));i++));
do
if [ "$DIR_IN" != "-" -a -d $DIR_OUT ]; then
	rm -rf $DIR_OUT
fi
if [[ $AFLGO == *good ]];then
	#gdb --args $AFLGO/afl-fuzz -m 100M -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
	/usr/bin/time -a -o $TIME_RECORD_FILE $AFLGO/afl-fuzz -m 100M -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR  $SUBJECT/${TARGET}_profiled @@
elif [[ $AFLGO == *origin ]];then
	#gdb --args $AFLGO/afl-fuzz -m 100M -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT $SUBJECT/${TARGET}_profiled @@
	/usr/bin/time -a -o $TIME_RECORD_FILE $AFLGO/afl-fuzz -m 100M -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT $SUBJECT/${TARGET}_profiled @@
fi
done

popd
