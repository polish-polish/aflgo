#!/bin/bash
if [ ! -n "$1" ] ;then
    echo "Please provide the program name as the first argument. e.g 'entry' for entry.c in samples directory."
    exit 1
fi
TARGET=$1
./compile_and_test_with_aflgo.sh $TARGET
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-good
SUBJECT=$AFLGO/tutorial/samples/test
TMP_DIR=$AFLGO/tutorial/samples/test/${TARGET}_temp
DIR_IN=${SUBJECT}/${TARGET}_in
DIR_OUT=${SUBJECT}/${TARGET}_out
ITER=40
cd $AFLGO/tutorial/samples/test


TIME1=1m
TIME2=2m
if [ "$TARGET" == "entry" ] ; then
	TIME1=1m
	TIME2=2m
elif [ "$TARGET" == "regex" ] ; then
	TIME1=1m
	TIME2=2m
elif [ "$TARGET" == "maze" ] ; then
	TIME1=30m
	TIME2=60m
fi
# cleanup time record
rm time${TIME1}-${TARGET}-aflgo-good.txt time${TIME2}-${TARGET}-aflgo-good.txt time${TIME1}-${TARGET}-aflgo-bad.txt time${TIME2}-${TARGET}-aflgo-bad.txt
:<<!
for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./${TARGET}_out
#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 1m -i in -o out -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
/usr/bin/time -a -o time${TIME1}-${TARGET}-aflgo-good.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME1 -i $DIR_IN -o $DIR_OUT -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
done 

for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./${TARGET}_out
#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 2m -i in -o out -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
/usr/bin/time -a -o time${TIME2}-${TARGET}-aflgo-good.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME2 -i $DIR_IN -o $DIR_OUT -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
done 
!

./compile_and_test_with_aflgo_origin.sh $TARGET
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-good
SUBJECT=$AFLGO/tutorial/samples/test
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-origin

for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./${TARGET}_out
/usr/bin/time -a -o time${TIME1}-${TARGET}-aflgo-bad.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME1 -i $DIR_IN -o $DIR_OUT $SUBJECT/${TARGET}_profiled @@
done 



for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./${TARGET}_out
/usr/bin/time -a -o time${TIME2}-${TARGET}-aflgo-bad.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME2 -i $DIR_IN -o $DIR_OUT $SUBJECT/${TARGET}_profiled @@
done 

echo time1m-${TARGET}-aflgo-good
./show-wall-time.sh time${TIME1}-${TARGET}-aflgo-good.txt
echo time2m-${TARGET}-aflgo-good
./show-wall-time.sh time${TIME2}-${TARGET}-aflgo-good.txt

echo time1m-${TARGET}-aflgo-bad
./show-wall-time.sh time${TIME1}-${TARGET}-aflgo-bad.txt
echo time2m-${TARGET}-aflgo-bad
./show-wall-time.sh time${TIME2}-${TARGET}-aflgo-bad.txt


