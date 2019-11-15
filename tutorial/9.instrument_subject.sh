#!/bin/bash

#previous environment add by yangke
export TMP_DIR=`pwd`/temp
export SUBJECT=`pwd`/libxml2



#export CFLAGS="$COPY_CFLAGS -distance=$TMP_DIR/distance.cfg.txt"
#export CXXFLAGS="$COPY_CXXFLAGS -distance=$TMP_DIR/distance.cfg.txt"
#export CFLAGS="-distance=$TMP_DIR/distance.cfg.txt"
#export CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt"
export CFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
export CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"

# Clean and build subject with distance instrumentation ☕️
pushd $SUBJECT
  make clean
  ./configure --disable-shared
  make -j$(nproc) all
popd


