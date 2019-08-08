#!/bin/bash
#wget http://releases.llvm.org/4.0.1/llvm-4.0.1.src.tar.xz
#wget http://releases.llvm.org/4.0.1/cfe-4.0.1.src.tar.xz
#wget http://releases.llvm.org/4.0.1/compiler-rt-4.0.1.src.tar.xz
#wget http://releases.llvm.org/4.0.1/libcxx-4.0.1.src.tar.xz
#wget http://releases.llvm.org/4.0.1/libcxxabi-4.0.1.src.tar.xz
#cd ~/Program/AFL/aflgo/llvm
#mkdir llvm-build
#cd llvm-build
export LLVM_DIR=llvm-4.0.1
export SRC=/home/yangke/Program/AFL/aflgo/llvm
export WORK=/home/yangke/Program/AFL/aflgo/llvm/llvm-build

# Build & install
mkdir -p $WORK/llvm
cd $WORK/llvm
cmake -G "Ninja" \
      -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
      -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86" \
      -DLLVM_BINUTILS_INCDIR=/usr/include $SRC/$LLVM_DIR
ninja
ninja install
rm -rf $WORK/llvm

mkdir -p $WORK/msan
cd $WORK/msan
cmake -G "Ninja" \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DLLVM_USE_SANITIZER=Memory -DCMAKE_INSTALL_PREFIX=/usr/msan/ \
      -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
      -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86" \
      $SRC/$LLVM_DIR
ninja cxx
ninja install-cxx
rm -rf $WORK/msan
