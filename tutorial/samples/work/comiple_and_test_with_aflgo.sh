#!/bin/bash
export AFLGO=/home/yangke/Program/AFL/aflgo/aflgo
export TMP_DIR=/home/yangke/Program/AFL/aflgo/aflgo/tutorial/samples/work/temp
export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
export LDFLAGS=-lpthread
export SUBJECT=/home/yangke/Program/AFL/aflgo/aflgo/tutorial/samples/work
if [ "$1" != "-" ] ; then
if [ ! -f ./entry.c ]; then
    exit 1
fi
if [ -d ./temp ] ;then
    rm -rf ./temp/*
else
    mkdir ./temp
fi
echo "entry.c:45"> ./temp/BBtargets.txt
pushd $AFLGO
make clean all 
cd $AFLGO/llvm_mode
make clean all
make
popd
export CC=$AFLGO/afl-clang-fast
gcc ./entry.c
$CC $ADDITIONAL $LDFLAGS  ./entry.c -o entry_profiled

# Clean up
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

# Generate distance ☕️
$AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR entry

echo "Distance values:"
head -n5 $TMP_DIR/distance.cfg.txt
echo "..."
tail -n5 $TMP_DIR/distance.cfg.txt


export CFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
export CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"

$CC $CFLAGS  ./entry.c -o entry_profiled

$AFLGO/scripts/index_all_cfg_edges.py -d $TMP_DIR/dot-files


# Construct seed corpus
if [ ! -d ./in ] ;then
    mkdir ./in
else
    rm ./in/*
fi
cp abc in
rm -rf ./out
fi
#gdb --args $AFLGO/afl-fuzz -S entry_result -z exp -c 2m -i in -o out $SUBJECT/entry_profiled @@
/usr/bin/time -a -o time.txt $AFLGO/afl-fuzz -S entry_result -z exp -c 1m -i in -o out -E $TMP_DIR $SUBJECT/entry_profiled @@

