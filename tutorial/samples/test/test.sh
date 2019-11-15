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
ITER=32
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
	TIME1=5m
	TIME2=10m
fi
# cleanup time record
if [ -f time${TIME1}-${TARGET}-aflgo-good.txt ];then
	rm time${TIME1}-${TARGET}-aflgo-good.txt
	rm time${TIME1}-${TARGET}-aflgo-good-statistics
fi
if [ -f time${TIME2}-${TARGET}-aflgo-good.txt ];then
	rm time${TIME2}-${TARGET}-aflgo-good.txt
	rm time${TIME2}-${TARGET}-aflgo-good-statistics
fi 
if [ -f time${TIME1}-${TARGET}-aflgo-bad.txt ];then
	rm time${TIME1}-${TARGET}-aflgo-bad.txt
fi
if [ -f time${TIME2}-${TARGET}-aflgo-bad.txt ];then
	rm time${TIME2}-${TARGET}-aflgo-bad.txt
fi

for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus

rm -rf ./${TARGET}_out
if [ "$TARGET" == "maze" ] ; then
/usr/bin/time -a -o time${TIME1}-${TARGET}-aflgo-good.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME1 -i $DIR_IN -o $DIR_OUT -x $SUBJECT/${TARGET}.dict -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
else
/usr/bin/time -a -o time${TIME1}-${TARGET}-aflgo-good.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME1 -i $DIR_IN -o $DIR_OUT -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
fi
cat $DIR_OUT/${TARGET}_result/statistics >> ./time${TIME1}-${TARGET}-aflgo-good-statistics
ERR_STR1=`grep "Command terminated by signal" ./time${TIME1}-${TARGET}-aflgo-good.txt  -n`
ERR_STR2=`grep "Command exited with non-zero status 1" ./time${TIME1}-${TARGET}-aflgo-good.txt  -n`
if [ "$ERR_STR1" != "" -o "$ERR_STR2" != "" ];then
	exit 1
fi
done

for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./${TARGET}_out
if [ "$TARGET" == "maze" ] ; then
#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 2m -i in -o out -x $SUBJECT/${TARGET}.dict -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
/usr/bin/time -a -o time${TIME2}-${TARGET}-aflgo-good.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME2 -i $DIR_IN -o $DIR_OUT -x $SUBJECT/${TARGET}.dict -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
else
#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c 2m -i in -o out -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
/usr/bin/time -a -o time${TIME2}-${TARGET}-aflgo-good.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME2 -i $DIR_IN -o $DIR_OUT -E $TMP_DIR $SUBJECT/${TARGET}_profiled @@
fi
ERR_STR1=`grep "Command terminated by signal" ./time${TIME1}-${TARGET}-aflgo-good.txt  -n`
ERR_STR2=`grep "Command exited with non-zero status 1" ./time${TIME1}-${TARGET}-aflgo-good.txt  -n`
if [ "$ERR_STR1" != "" -o "$ERR_STR2" != "" ];then
	exit 1
fi
cat $DIR_OUT/${TARGET}_result/statistics >> ./time${TIME2}-${TARGET}-aflgo-good-statistics
done
:<<!
./compile_and_test_with_aflgo_origin.sh $TARGET
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-good
SUBJECT=$AFLGO/tutorial/samples/test
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-origin

for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./${TARGET}_out
if [ "$TARGET" == "maze" ] ; then
/usr/bin/time -a -o time${TIME1}-${TARGET}-aflgo-bad.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME1 -i $DIR_IN -o $DIR_OUT -x $SUBJECT/${TARGET}.dict $SUBJECT/${TARGET}_profiled @@
else
/usr/bin/time -a -o time${TIME1}-${TARGET}-aflgo-bad.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME1 -i $DIR_IN -o $DIR_OUT $SUBJECT/${TARGET}_profiled @@
fi
done 

for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./${TARGET}_out
if [ "$TARGET" == "maze" ] ; then
/usr/bin/time -a -o time${TIME2}-${TARGET}-aflgo-bad.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME2 -i $DIR_IN -o $DIR_OUT -x $SUBJECT/${TARGET}.dict $SUBJECT/${TARGET}_profiled @@
else
/usr/bin/time -a -o time${TIME2}-${TARGET}-aflgo-bad.txt $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME2 -i $DIR_IN -o $DIR_OUT $SUBJECT/${TARGET}_profiled @@
fi
done 
!
:<<!
echo time${TIME1}-${TARGET}-aflgo-good
./show-wall-time.sh time${TIME1}-${TARGET}-aflgo-good.txt
echo time${TIME2}-${TARGET}-aflgo-good
./show-wall-time.sh time${TIME2}-${TARGET}-aflgo-good.txt

echo time${TIME1}-${TARGET}-aflgo-bad
./show-wall-time.sh time${TIME1}-${TARGET}-aflgo-bad.txt
echo time${TIME2}-${TARGET}-aflgo-bad
./show-wall-time.sh time${TIME2}-${TARGET}-aflgo-bad.txt
!

