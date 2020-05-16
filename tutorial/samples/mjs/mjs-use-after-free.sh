#!/bin/bash
pushd `pwd`
WORK=`pwd`
NAME=mjs

if [ "$1" == "good" ];then
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-good
cd $AFLGO && make clean all && cd - &&  cd $AFLGO/llvm_mode && make clean all && cd -
DOWNLOAD_DIR=$WORK/build_good_${NAME}
elif [ "$1" == "bad" ];then
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-origin
DOWNLOAD_DIR=$WORK/build_bad_${NAME}
elif [ "$1" != "-" ];then
echo "INVALID 1st ARGUMENT:$1"
exit
fi


TARGET=mjs-use-after-free
if [ ! -d $DOWNLOAD_DIR ]; then
mkdir $DOWNLOAD_DIR
fi 
cd $DOWNLOAD_DIR

SUBJECT=$DOWNLOAD_DIR
TMP_DIR=$SUBJECT/temp
#PATCH="patch-9eae0e6-use-after-free-for-fuzz"

if [ "$1" != "-" ] ; then
	if [ -d $TMP_DIR ]; then
		rm -rf $TMP_DIR
	fi
	mkdir $TMP_DIR
	#Testing for issue 78
	#https://github.com/cesanta/mjs/issues/78
	[ ! -d mjs ] && git clone https://github.com/cesanta/mjs && cd mjs && git checkout 9eae0e6 && cd ..
	
	#setup targets
	cd ./mjs && git checkout mjs.c && git checkout 9eae0e6 && cd - 

	echo -e "mjs.c:13679\nmjs.c:13687\nmjs.c:13927\nmjs.c:13706\nmjs.c:13718\nmjs.c:14146\nmjs.c:4924\n" >$TMP_DIR/BBtargets.txt

	ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"

	export CC=$AFLGO/afl-clang-fast
	export CXX=$AFLGO/afl-clang-fast++
	sed "8 cDOCKER_GCC = $AFLGO/afl-clang-fast" -i mjs/mjs/Makefile
	sed "9 cDOCKER_CLANG = $AFLGO/afl-clang-fast" -i mjs/mjs/Makefile

	export CFLAGS="-g3 $ADDITIONAL"

	
	export CXXFLAGS="-g3 $ADDITIONAL"
	export LDFLAGS="-lpthread"
	
	#sed '76 s/$(TOP_SOURCES)/$(TOP_SOURCES) -lpthread' -i mjs/mjs/Makefile
	export AR=llvm-ar 
        export AR_FLAGS=cr
        export RANLIB=llvm-ranlib

	#1st compile
	pwd
	echo "$CC ./mjs.c -DMJS_MAIN $CFLAGS -ldl -g -o mjs/build/$TARGET"
        
	cd mjs && $CC ./mjs.c -DMJS_MAIN $CFLAGS -ldl -g -o mjs/mjs && cd -
	# Clean up
	cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
	cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

	# Generate distance

	$AFLGO/scripts/genDistance.sh $SUBJECT/mjs/mjs $TMP_DIR ${TARGET}

	echo "Distance values:"
	head -n5 $TMP_DIR/distance.cfg.txt
	echo "..."
	tail -n5 $TMP_DIR/distance.cfg.txt

	CFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
	CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"

	#2nd compile
	if [ -d $TMP_DIR/rid_bbname_pairs ];then
		rm -rf $TMP_DIR/rid_bbname_pairs $TMP_DIR/index
	fi
	export AFL_USE_ASAN=1
	cd mjs && $CC ./mjs.c -DMJS_MAIN $CFLAGS -ldl -g -o mjs/$TARGET && cd -
	
	cd $SUBJECT
	if [[ $AFLGO == *good ]];then
		$AFLGO/scripts/index_all_cfg_edges.py -t $TMP_DIR
	#	#$AFLGO/tutorial/samples/test/vis-dot.sh $TMP_DIR/dot-files
	fi
fi


TIME=40m
DIR_IN=$DOWNLOAD_DIR/mjs/mjs/tests
DIR_OUT=$DOWNLOAD_DIR/out

TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-good.txt
if [[ $AFLGO == *good ]];then
	TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-good.txt
elif [[ $AFLGO == *origin ]];then
	TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-bad.txt
fi
if [ -f $TIME_RECORD_FILE ]; then
	rm $TIME_RECORD_FILE
fi
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/
ITER=20
rm -rf ${TARGET}-tmp-results
mkdir ${TARGET}-tmp-results
for((i=1;i<=$((ITER));i++));
do
if [ "$DIR_IN" != "-" -a -d $DIR_OUT ]; then
	rm -rf $DIR_OUT
fi
if [[ $AFLGO == *good ]];then
	#gdb --args $AFLGO/afl-fuzz -m 100M -S ${TARGET}_$((i))_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR $SUBJECT/mjs/mjs/$TARGET @@
	#/usr/bin/time -a -o $TIME_RECORD_FILE $AFLGO/afl-fuzz -m 100M -S ${TARGET}_$((i))_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR  $SUBJECT/mjs/mjs/$TARGET @@
        $AFLGO/afl-fuzz -m none -S ${TARGET}_$((i))_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR  $SUBJECT/mjs/mjs/$TARGET @@
	if [ "$?" != 0 ];then
		exit
	fi
elif [[ $AFLGO == *origin ]];then
	#gdb --args $AFLGO/afl-fuzz -m 100M -S ${TARGET}_$((i))_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT $SUBJECT/mjs/mjs/$TARGET @@
	#/usr/bin/time -a -o $TIME_RECORD_FILE $AFLGO/afl-fuzz -m 100M -S ${TARGET}_$((i))_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT $SUBJECT/mjs/mjs/$TARGET @@
	$AFLGO/afl-fuzz -m 100M -S ${TARGET}_$((i))_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT $SUBJECT/mjs/mjs/$TARGET @@
	if [ "$?" != 0 ];then
		exit
	fi
fi
mv $DIR_OUT/${TARGET}_$((i))_result  ${TARGET}-tmp-results/${TARGET}_$((i))_result
done
mv ${TARGET}-tmp-results/${TARGET}_*_result $DIR_OUT/
popd
