#!/bin/bash

#previous environment add by yangke
export WORK=/home/yangke/Program/AFL/aflgo/bak/aflgo-good/tutorial
export TMP_DIR=$WORK/temp
export SUBJECT=$WORK/libxml2
export AFLGO=$WORK/..

#Construct seed corpus
if [ ! -d "./in" ]; then
  mkdir in
fi
#for xmllint test#
#cp $SUBJECT/test/dtd* in
#cp $SUBJECT/test/dtds/* in
#for testXPath test
cp $SUBJECT/test/XPath/xptr/chaptersrange in

#default
input="in"
echo $#
if [ $# -eq 1 ]; then
  echo yes
  if [ '-' ne $1 ]; then
    echo "To start a new fuzzing:"
    echo "./10.construct_seed_corpus_and_fuzz.sh"
    echo "To resume the previous fuzzing:"
    echo "./10.construct_seed_corpus_and_fuzz.sh -"
    exit 1
  else
    input='-'
  fi
fi
#echo "$AFLGO/afl-fuzz -S ef709ce2 -z exp -c 45m -i $input -o out -E $TMP_DIR $SUBJECT/xmllint --valid --recover @@"
#$AFLGO/afl-fuzz -S ef709ce2 -z exp -c 45m -i $input -o out -E $TMP_DIR $SUBJECT/xmllint --valid --recover @@
echo "$AFLGO/afl-fuzz -S ef709ce2 -z exp -c 45m -i $input -o out -E $TMP_DIR $SUBJECT/testXPath --xptr -i /home/yangke/Program/AFL/aflgo/bak/aflgo-good/tutorial/libxml2/test/XPath/docs/chapters -f @@"
#$AFLGO/afl-fuzz -S ef709ce2 -z exp -c 45m -i $input -o out -E $TMP_DIR $SUBJECT/testXPath --xptr -i $SUBJECT/test/XPath/docs/chapters -f @@
$AFLGO/afl-fuzz -S ef709ce2 -z exp -c 45m -i - -o out -E $TMP_DIR $SUBJECT/testXPath --xptr -i $SUBJECT/test/XPath/docs/chapters -f @@


