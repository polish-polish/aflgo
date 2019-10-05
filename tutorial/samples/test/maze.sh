#!/bin/bash
~/Program/AFL/afl-2.35b/afl-gcc ./maze.c -o maze_profiled
cd ~/Program/AFL/aflgo/bak/aflgo-good/tutorial/samples/test
rm -rf maze_findings
mkdir ./maze_testcases
#known answers
#ssssddddwwaawwddddssssddwwww
#ssssddddwwaawwddddsddwwdwww
echo awsd > ./maze_testcases/answer1
~/Program/AFL/afl-2.35b/afl-fuzz -i maze_testcases -m 100 -o maze_findings ./maze_profiled @@

