#!/bin/bash
pushd `pwd`
TEST_SUITE_DIR=/home/yangke/Program/AFL/aflgo/fuzzer-test-suite
DOWNLOAD_DIR=/home/yangke/Program/AFL/aflgo/build_libpng-1.2.56
cd $DOWNLOAD_DIR
#rm -rf ./BUILD
SUBJECT=$TEST_SUITE_DIR/libpng-1.2.56
TMP_DIR=$SUBJECT/temp
if [ ! -d $TMP_DIR ]; then
mkdir $TMP_DIR
fi
echo "pngread.c:738" >$TMP_DIR/BBtargets.txt 
#$TEST_SUITE_DIR/libpng-1.2.56/build.sh
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-origin

cd $DOWNLOAD_DIR/BUILD/
ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"

export CC=$AFLGO/afl-clang-fast
export CXX=$AFLGO/afl-clang-fast++

export CFLAGS="-g3 $ADDITIONAL"
export CXXFLAGS="-g3 $ADDITIONAL"
export LDFLAGS="-lpthread"
#./configure && make
cd $SUBJECT
TARGET=target
$CXX $CXXFLAGS $LDFLAGS -std=c++11 -v  $TEST_SUITE_DIR/libpng-1.2.56/target.cc $TEST_SUITE_DIR/examples/example-hooks.cc $DOWNLOAD_DIR/BUILD/.libs/libpng12.a -I $DOWNLOAD_DIR/BUILD/ -lz -o ${TARGET}_profiled

# Clean up
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

# Generate distance

#cp $TEST_SUITE_DIR/libpng-1.2.56/target.cc $TEST_SUITE_DIR/libpng-1.2.56/target.c
#$AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR ${TARGET}

echo "Distance values:"
head -n5 $TMP_DIR/distance.cfg.txt
echo "..."
tail -n5 $TMP_DIR/distance.cfg.txt


CFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
cd $DOWNLOAD_DIR/BUILD/
make clean && ./configure && make
cd $SUBJECT 
$CXX $CXXFLAGS $LDFLAGS -std=c++11 -v  $TEST_SUITE_DIR/libpng-1.2.56/target.cc $TEST_SUITE_DIR/examples/example-hooks.cc $DOWNLOAD_DIR/BUILD/.libs/libpng12.a -I $DOWNLOAD_DIR/BUILD/ -lz -o ${TARGET}_profiled


TIME=1m
DIR_IN=$TEST_SUITE_DIR/libpng-1.2.56/seeds
DIR_OUT=$DOWNLOAD_DIR/out

/usr/bin/time -a -o time.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -x $AFLGO/dictionaries/png.dict $SUBJECT/${TARGET}_profiled @@
popd
