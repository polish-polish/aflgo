#!/bin/bash
pushd `pwd`
TEST_SUITE_DIR=/home/yangke/Program/AFL/aflgo/fuzzer-test-suite
DOWNLOAD_DIR=/home/yangke/Program/AFL/aflgo/build_good_libpng-1.2.56
if [ ! -d $DOWNLOAD_DIR ]; then
mkdir $DOWNLOAD_DIR
fi 
cd $DOWNLOAD_DIR
#SUBJECT=$TEST_SUITE_DIR/libpng-1.2.56
SUBJECT=$DOWNLOAD_DIR
TMP_DIR=$SUBJECT/temp
##if [ -d $TMP_DIR ]; then
##rm -rf $TMP_DIR
##fi
##mkdir $TMP_DIR
echo "pngread.c:738" >$TMP_DIR/BBtargets.txt 
#$TEST_SUITE_DIR/libpng-1.2.56/build.sh
##[ ! -e libpng-1.2.56.tar.gz ] && wget https://downloads.sourceforge.net/project/libpng/libpng12/older-releases/1.2.56/libpng-1.2.56.tar.gz
##[ ! -e libpng-1.2.56 ] && tar xf libpng-1.2.56.tar.gz
##rm -rf ./BUILD
##cp -rf libpng-1.2.56 BUILD
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-good

cd $DOWNLOAD_DIR/BUILD/
ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"

export CC=$AFLGO/afl-clang-fast
export CXX=$AFLGO/afl-clang-fast++

export CFLAGS="-g3 $ADDITIONAL"
export CXXFLAGS="-g3 $ADDITIONAL"
export LDFLAGS="-lpthread"
##./configure
##make
cd $SUBJECT
TARGET=target
##$CXX $CXXFLAGS $LDFLAGS -std=c++11 -v  $TEST_SUITE_DIR/libpng-1.2.56/target.cc $TEST_SUITE_DIR/examples/example-hooks.cc $DOWNLOAD_DIR/BUILD/.libs/libpng12.a -I $DOWNLOAD_DIR/BUILD/ -lz -o ${TARGET}_profiled

# Clean up
##cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
##cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

# Generate distance

##$AFLGO/scripts/genDistance.sh $TEST_SUITE_DIR/libpng-1.2.56 $TMP_DIR ${TARGET}

##echo "Distance values:"
##head -n5 $TMP_DIR/distance.cfg.txt
##echo "..."
##tail -n5 $TMP_DIR/distance.cfg.txt


CFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
cd $DOWNLOAD_DIR/BUILD/
##make clean && ./configure  && make

cd $SUBJECT 
##$CXX $CXXFLAGS $LDFLAGS -std=c++11 -v  $TEST_SUITE_DIR/libpng-1.2.56/target.cc $TEST_SUITE_DIR/examples/example-hooks.cc $DOWNLOAD_DIR/BUILD/.libs/libpng12.a -I $DOWNLOAD_DIR/BUILD/ -lz -o ${TARGET}_profiled

$AFLGO/scripts/index_all_cfg_edges.py -d $TMP_DIR/dot-files
$AFLGO/tutorial/samples/test/vis-dot.sh $TMP_DIR/dot-files

TIME=1m
DIR_IN=$TEST_SUITE_DIR/libpng-1.2.56/seeds
DIR_OUT=$DOWNLOAD_DIR/out
if [ -d $DIR_OUT ]; then
rm -rf $DIR_OUT
fi
/usr/bin/time -a -o time.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR -x $AFLGO/dictionaries/png.dict $SUBJECT/${TARGET}_profiled @@
popd
