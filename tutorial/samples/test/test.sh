#!/bin/bash
./compile_and_test_with_aflgo.sh
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
#gdb --args $AFLGO/afl-fuzz -S entry_result -z exp -c 1m -i in -o out -E $TMP_DIR $SUBJECT/entry_profiled @@
/usr/bin/time -a -o time1m-aflgo-good.txt $AFLGO/afl-fuzz -S entry_result -z exp -c 1m -i in -o out -E $TMP_DIR $SUBJECT/entry_profiled @@
done 

for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./out
#gdb --args $AFLGO/afl-fuzz -S entry_result -z exp -c 2m -i in -o out -E $TMP_DIR $SUBJECT/entry_profiled @@
/usr/bin/time -a -o time2m-aflgo-good.txt $AFLGO/afl-fuzz -S entry_result -z exp -c 2m -i in -o out -E $TMP_DIR $SUBJECT/entry_profiled @@
done 


./compile_and_test_with_aflgo_origin.sh
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-good
SUBJECT=$AFLGO/tutorial/samples/test
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-origin


for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./out
/usr/bin/time -a -o time1m-aflgo-bad.txt $AFLGO/afl-fuzz -S entry_result -z exp -c 1m -i in -o out $SUBJECT/entry_profiled @@
done 



for((i=1;i<=$((ITER));i++));  
do
# Construct seed corpus
rm -rf ./out
/usr/bin/time -a -o time2m-aflgo-bad.txt $AFLGO/afl-fuzz -S entry_result -z exp -c 2m -i in -o out $SUBJECT/entry_profiled @@
done 

echo time1m-aflgo-good
./show-wall-time.sh time1m-aflgo-good.txt
echo time2m-aflgo-good
./show-wall-time.sh time2m-aflgo-good.txt

echo time1m-aflgo-bad
./show-wall-time.sh time1m-aflgo-bad.txt
echo time2m-aflgo-bad
./show-wall-time.sh time2m-aflgo-bad.txt

