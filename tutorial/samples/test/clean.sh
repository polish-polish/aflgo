#!/bin/bash
pgrep "compile_and_test_with" |xargs kill -s 9
pgrep "test.sh" |xargs kill -s 9
rm -rf ./*_temp ./*_out ./*_in a.out *.bc *.ll *.o *.txt entry regex maze *profiled

