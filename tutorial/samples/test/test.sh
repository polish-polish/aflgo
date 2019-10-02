#!/bin/bash
if [ ! -n "$1" ] ;then
    echo "Please provide the program name as the first argument. e.g 'entry' for entry.c in samples directory."
    exit 1
fi
TARGET=$1
./compile_and_test_with_aflgo.sh $TARGET
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-good
SUBJECT=$AFLGO/tutorial/samples/test
TMP_DIR=$AFLGO/tutorial/samples/test/temp
ITER=60
cd $AFLGO/tutorial/samples/test

rm ./time*
for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./out
#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 1m -i in -o out -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
/usr/bin/time -a -o time1m-${TARGET}-aflgo-good.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 1m -i in -o out -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
done 

for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./out
#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 2m -i in -o out -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
/usr/bin/time -a -o time2m-${TARGET}-aflgo-good.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 2m -i in -o out -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
done 


./compile_and_test_with_aflgo_origin.sh
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-good
SUBJECT=$AFLGO/tutorial/samples/test
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-origin


for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./out
/usr/bin/time -a -o time1m-${TARGET}-aflgo-bad.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 1m -i in -o out $SUBJECT/${TARGET}_profiled @@
done 



for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./out
/usr/bin/time -a -o time2m-${TARGET}-aflgo-bad.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 2m -i in -o out $SUBJECT/${TARGET}_profiled @@
done 

echo time1m-${TARGET}-aflgo-good
./show-wall-time.sh time1m-${TARGET}-aflgo-good.txt
echo time2m-${TARGET}-aflgo-good
./show-wall-time.sh time2m-${TARGET}-aflgo-good.txt

echo time1m-${TARGET}-aflgo-bad
./show-wall-time.sh time1m-${TARGET}-aflgo-bad.txt
echo time2m-${TARGET}-aflgo-bad
./show-wall-time.sh time2m-${TARGET}-aflgo-bad.txt

