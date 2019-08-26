#!/bin/bash
AFLGO=/home/yangke/Program/AFL/aflgo/tutorial/aflgo-good
SUBJECT=/home/yangke/Program/AFL/aflgo/tutorial/samples/test

for((i=1;i<=60;i++));  
do
# Construct seed corpus
rm -rf ./out
/usr/bin/time -a -o time1m-aflgo-good.txt $AFLGO/afl-fuzz -S entry_result -z exp -c 1m -i in -o out $SUBJECT/entry_profiled @@
done 



for((i=1;i<=60;i++));  
do
# Construct seed corpus
rm -rf ./out
/usr/bin/time -a -o time2m-aflgo-good.txt $AFLGO/afl-fuzz -S entry_result -z exp -c 2m -i in -o out $SUBJECT/entry_profiled @@
done 


AFLGO=/home/yangke/Program/AFL/aflgo/tutorial/aflgo-bad
SUBJECT=/home/yangke/Program/AFL/aflgo/tutorial/samples/test

for((i=1;i<=60;i++));  
do
# Construct seed corpus
rm -rf ./out
/usr/bin/time -a -o time1m-aflgo-bad.txt $AFLGO/afl-fuzz -S entry_result -z exp -c 1m -i in -o out $SUBJECT/entry_profiled @@
done 



for((i=1;i<=60;i++));  
do
# Construct seed corpus
rm -rf ./out
/usr/bin/time -a -o time2m-aflgo-bad.txt $AFLGO/afl-fuzz -S entry_result -z exp -c 2m -i in -o out $SUBJECT/entry_profiled @@
done 

