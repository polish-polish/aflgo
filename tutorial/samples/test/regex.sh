#!/bin/bash
~/Program/AFL/afl-2.35b/afl-gcc ./regex.c -o regex_profiled
cd ~/Program/AFL/aflgo/bak/aflgo-good/tutorial/samples/test
mkdir ./regex_testcases
echo "abc" > ./regex_testcases/words
/usr/bin/time -a -o time.txt ~/Program/AFL/afl-2.35b/afl-fuzz -i regex_testcases -o regex_findings ./regex_profiled @@
