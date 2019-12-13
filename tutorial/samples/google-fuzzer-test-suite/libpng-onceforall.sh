#!/bin/bash
pushd `pwd`
WORK=`pwd`
NAME=libpng-1.2.56
TEST_SUITE_DIR=$WORK/fuzzer-test-suite

if [ "$1" == "good" ];then
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-good
DOWNLOAD_DIR_PREFIX=$WORK/build_good
elif [ "$1" == "bad" ];then
AFLGO=/home/yangke/Program/AFL/aflgo/bak/aflgo-origin
DOWNLOAD_DIR_PREFIX=$WORK/build_bad
elif [ "$1" != "-" ];then 
echo "INVALID 1st ARGUMENT:$1"
exit
fi

if [ "$2" == "pngread" ];then
TARGET=pngread
NAME=libpng-1.2.56
elif [ "$2" == "pngrutil" ];then
TARGET=pngrutil
NAME=libpng-1.2.56
elif [ "$2" == "CVE-2011-2501" ];then
TARGET=pngerror
NAME=CVE-2011-2501
elif [ "$2" != "-" ] ; then
echo "INVALID 2nd ARGUMENT:$2"
exit
fi
DOWNLOAD_DIR=${DOWNLOAD_DIR_PREFIX}_${NAME}
if [ ! -d $DOWNLOAD_DIR ]; then
mkdir $DOWNLOAD_DIR
fi 
cd $DOWNLOAD_DIR
SUBJECT=$DOWNLOAD_DIR
TMP_DIR=$SUBJECT/temp

if [ "$2" != "-" ] ; then
	if [ -d $TMP_DIR ]; then
		rm -rf $TMP_DIR
	fi
	mkdir $TMP_DIR

	#download PUT
	rm -rf ./BUILD
	
	if [ "$TARGET" = "pngread" -o "$TARGET" = "pngrutil" ];then
		##[ ! -e libpng-1.2.56.tar.gz ] && wget https://downloads.sourceforge.net/project/libpng/libpng12/older-releases/1.2.56/libpng-1.2.56.tar.gz
		##[ ! -d libpng-1.2.56 ] && tar xf libpng-1.2.56.tar.gz
		cp -R libpng-1.2.56 BUILD 
	elif [ "$TARGET" == "pngerror" ];then
		#CVE-2011-2501 pngerror.c:184  version:libpng-1.2.44
		[ ! -d ./libpng ] && git clone https://github.com/glennrp/libpng.git && cd libpng && git checkout 72c637e && cd ..
		cp -R libpng BUILD
	fi
	#setup targets
	if [ "$TARGET" == "pngread" ];then
		if [ "`sed -n 740p  BUILD/pngread.c`" != "abort();" ] ;then
			sed "739 aabort();" -i BUILD/pngread.c
		fi
		echo -e "pngread.c:739\npngread.c:740" >$TMP_DIR/BBtargets.txt
	elif [ "$TARGET" == "pngrutil" ];then
		if [ "`sed -n 3184p  BUILD/pngrutil.c`" != "abort();" ] ;then
			sed "3183 aabort();" -i BUILD/pngrutil.c
		fi
		echo -e "pngrutil.c:3183\npngrutil.c:3184" >$TMP_DIR/BBtargets.txt
	elif [ "$TARGET" == "pngerror" ];then
		if [ "`sed -n 184p  BUILD/pngerror.c`" != "abort();" ] ;then
			sed "183 aabort();" -i BUILD/pngerror.c
		fi
		echo -e "pngerror.c:183\npngerror.c:184" >$TMP_DIR/BBtargets.txt
	fi

	#set c or cxx flags
	SEC_FLAGS=""
	if [ $TARGET="pngerror" ];then
		SEC_FLAGS="" #"-fsanitize=address,undefined -Wformat -Werror=format-security -Werror=array-bounds"	
	fi
	cd $DOWNLOAD_DIR/BUILD/
	ADDITIONAL="$SEC_FLAGS -targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"

	export CC=$AFLGO/afl-clang-fast
	export CXX=$AFLGO/afl-clang-fast++

	export CFLAGS="-g3 $ADDITIONAL"
	export CXXFLAGS="-g3 $ADDITIONAL"
	export LDFLAGS="-lpthread"

	#1st compile
	./configure --disable-shared
	make
	cd $SUBJECT
	$CXX $CXXFLAGS $LDFLAGS -std=c++11 -v  $TEST_SUITE_DIR/libpng-1.2.56/target.cc $TEST_SUITE_DIR/examples/example-hooks.cc $DOWNLOAD_DIR/BUILD/.libs/libpng12.a -I $DOWNLOAD_DIR/BUILD/ -lz -o ${TARGET}_profiled

	# Clean up
	cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
	cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

	# Generate distance

	$AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR ${TARGET}_profiled

	echo "Distance values:"
	head -n5 $TMP_DIR/distance.cfg.txt
	echo "..."
	tail -n5 $TMP_DIR/distance.cfg.txt


	CFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"
	CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt -outdir=$TMP_DIR"

	#2nd compile
	cd $DOWNLOAD_DIR/BUILD/	
	make clean && ./configure --disable-shared  && make
	cd $SUBJECT 
	$CXX $CXXFLAGS $LDFLAGS -std=c++11 -v  $TEST_SUITE_DIR/libpng-1.2.56/target.cc $TEST_SUITE_DIR/examples/example-hooks.cc $DOWNLOAD_DIR/BUILD/.libs/libpng12.a -I $DOWNLOAD_DIR/BUILD/ -lz -o ${TARGET}_profiled
	if [[ $AFLGO == *good ]];then
		$AFLGO/scripts/index_all_cfg_edges.py -d $TMP_DIR/dot-files
		#$AFLGO/tutorial/samples/test/vis-dot.sh $TMP_DIR/dot-files
	fi	
fi

if [ "$2" != "-" ] ; then
	DIR_IN=$DOWNLOAD_DIR/in
	if [ ! -d $DIR_IN ]; then
		mkdir $DIR_IN
		#cp $TEST_SUITE_DIR/libpng-1.2.56/oom-63efa8b5a2adf76dc225d62939db3337ff6774f1 $DIR_IN
		if [ "$TARGET" = "pngread" -o "$TARGET" = "pngrutil" ];then
			cp $TEST_SUITE_DIR/libpng-1.2.56/seeds/seed.png $DIR_IN
		elif [ "$TARGET" == "pngerror" ];then
			cp $AFLGO/testcases/images/png/* $DIR_IN
		fi
			
	fi
else
	DIR_IN="-"
fi



TIME=1m

DIR_OUT=$DOWNLOAD_DIR/out


TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-good.txt
if [[ $1 == *good* ]];then
	TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-good.txt
elif [[ $1 == *bad* ]];then
	TIME_RECORD_FILE=time${TIME}-${TARGET}-${NAME}-aflgo-bad.txt
fi
if [ -f $TIME_RECORD_FILE ]; then
	rm $TIME_RECORD_FILE
fi

ITER=1
for((i=1;i<=$((ITER));i++));
do
if [ "$DIR_IN" != "-" -a -d $DIR_OUT ]; then
	rm -rf $DIR_OUT
fi
if [[ $AFLGO == *good ]];then
	#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR -x $AFLGO/dictionaries/png.dict $SUBJECT/${TARGET}_profiled @@
	/usr/bin/time -a -o $TIME_RECORD_FILE $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -E $TMP_DIR -x $AFLGO/dictionaries/png.dict $SUBJECT/${TARGET}_profiled @@
elif [[ $AFLGO == *origin ]];then
	#gdb --args $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -x $AFLGO/dictionaries/png.dict $SUBJECT/${TARGET}_profiled @@
	/usr/bin/time -a -o $TIME_RECORD_FILE $AFLGO/afl-fuzz -S ${TARGET}_result -z exp -c $TIME -i $DIR_IN -o $DIR_OUT -x $AFLGO/dictionaries/png.dict $SUBJECT/${TARGET}_profiled @@
fi
done
popd
