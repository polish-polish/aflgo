#!/bin/bash
# Checkout source code
#git clone https://github.com/aflgo/aflgo.git
export AFLGO=$PWD/aflgo

# Compile source code
pushd $AFLGO
make clean all 
cd llvm_mode
make clean all
popd
