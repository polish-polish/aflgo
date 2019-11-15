/*
 american fuzzy lop - LLVM-mode instrumentation pass
 ---------------------------------------------------

 Written by Laszlo Szekeres <lszekeres@google.com> and
 Michal Zalewski <lcamtuf@google.com>

 LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
 from afl-as.c are Michal's fault.

 Copyright 2015, 2016 Google Inc. All rights reserved.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at:

 http://www.apache.org/licenses/LICENSE-2.0

 This library is plugged into LLVM when invoking clang through afl-clang-fast.
 It tells the compiler to add code roughly equivalent to the bits discussed
 in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif
/*add by yangke start*/
#include "llvm/IR/Type.h"
/*add by yangke end*/
#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

using namespace llvm;

cl::opt<std::string> DistanceFile("distance",
		cl::desc(
				"Distance file containing the distance of each basic block to the provided targets."),
		cl::value_desc("filename"));

cl::opt<std::string> TargetsFile("targets",
		cl::desc("Input file containing the target lines of code."),
		cl::value_desc("targets"));

cl::opt<std::string> OutDirectory("outdir",
		cl::desc(
				"Output directory where Ftargets.txt, Fnames.txt, and BBnames.txt are generated."),
		cl::value_desc("outdir"));

namespace {

class AFLCoverage: public ModulePass {

public:

	static char ID;
	/* add by yangke start */
	static unsigned instrument_cnt;
	static unsigned lattice;//Control bits of Shl operation for value to store: 0,8,16,24(4B) or 0,8,16,24,32,40,48,56(8B)
	/* add by yangke end */
	AFLCoverage() :
			ModulePass(ID) {
	}

	bool runOnModule(Module &M) override;
protected:
	void mapValue(Value *insert_point, Value *v, GlobalVariable *AFLMapPtr,
			GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
			unsigned int cur_loc);
	size_t hashName(Value *v);
	void debug(Value *v,std::string info="#Value#--");
	void bbRecord(unsigned int cur_loc, BasicBlock &BB,
			std::ofstream &bbname_id_pairs);
	void handleGetElementPtrInst(Value *insert_point, GetElementPtrInst * GEPI, GlobalVariable *AFLMapPtr,
			GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
			unsigned int cur_loc);
	void handleLoadInst(Value *insert_point, LoadInst * LI, GlobalVariable *AFLMapPtr,
			GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
			unsigned int cur_loc);
	void handleCastInst(Value *insert_point, CastInst * CI, GlobalVariable *AFLMapPtr,
			GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
			unsigned int cur_loc);
	void handleICmpInst(Value *insert_point, ICmpInst * ICmp, GlobalVariable *AFLMapPtr,
			GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
			unsigned int cur_loc);
	void handleFCmpInst(Value *insert_point, FCmpInst * FCmp, GlobalVariable *AFLMapPtr,
				GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
				unsigned int cur_loc);
	void handleBinaryOperator(Value *insert_point, BinaryOperator * BOP, GlobalVariable *AFLMapPtr,
			GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
			unsigned int cur_loc);
};

}

char AFLCoverage::ID = 0;
/* add by yangke start */
unsigned AFLCoverage::instrument_cnt = 0;
unsigned AFLCoverage::lattice = 0;
/* add by yangke end */
void AFLCoverage::bbRecord(unsigned int cur_loc, BasicBlock &BB,
		std::ofstream &bbname_id_pairs) {
	std::string bb_name("");
	std::string filename;
	unsigned line;
	for (auto &I : BB) {
#ifdef LLVM_OLD_DEBUG_API
		DebugLoc Loc = I.getDebugLoc();
		if (!Loc.isUnknown()) {

			DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
			DILocation oDILoc = cDILoc.getOrigLocation();

			line = oDILoc.getLineNumber();
			filename = oDILoc.getFilename().str();

			if (filename.empty()) {
				line = cDILoc.getLineNumber();
				filename = cDILoc.getFilename().str();
			}
#else

		if (DILocation *Loc = I.getDebugLoc()) {
			line = Loc->getLine();
			filename = Loc->getFilename().str();

			if (filename.empty()) {
				DILocation *oDILoc = Loc->getInlinedAt();
				if (oDILoc) {
					line = oDILoc->getLine();
					filename = oDILoc->getFilename().str();
				}
			}

#endif /* LLVM_OLD_DEBUG_API */

			/* Don't worry about external libs */
			std::string Xlibs("/usr/");
			if (filename.empty() || line == 0
					|| !filename.compare(0, Xlibs.size(), Xlibs))
				continue;

			if (bb_name.empty()) {

				std::size_t found = filename.find_last_of("/\\");
				if (found != std::string::npos)
					filename = filename.substr(found + 1);

				bb_name = filename + ":" + std::to_string(line);
				break;
			}
		}
	}
	bbname_id_pairs << bb_name << "," << cur_loc << "\n";
}
inline void AFLCoverage::debug(Value *v,std::string info) { //contains format string vulnerability
#ifdef DEBUG_
	std::string var_str;
	llvm::raw_string_ostream rso(var_str);
	v->print(rso);
	OKF("%s:%s", info.c_str(), var_str.c_str());
#endif
}
void AFLCoverage::handleGetElementPtrInst(Value *insert_point, GetElementPtrInst * GEPI, GlobalVariable *AFLMapPtr,
		GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
		unsigned int cur_loc) {
	if(GEPI->isInBounds ()&& GEPI->hasIndices()){//getNumOperands()>1
		int num=GEPI->getNumOperands();
		//skip 0 op(PointerOperands)
		for(int i=1;i<num;i++){
			Value * gep_op=GEPI->getOperand(i);
			if(Constant * c = dyn_cast < Constant > (gep_op)){
			}else if (gep_op->getType()->getTypeID() != Type::VoidTyID) {
				mapValue(insert_point, gep_op, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
				if (CastInst * CI = dyn_cast < CastInst > (gep_op)){
					debug(gep_op,"#GetElementPtr depends on indice(CastInst):#");
					handleCastInst(insert_point, CI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
				}else if (LoadInst * LI = dyn_cast < LoadInst > (gep_op)) {
					debug(gep_op,"#GetElementPtr depends on indice(LoadInst):#");
					handleLoadInst(insert_point, LI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
				}
			}
		}
		Value * ptr=GEPI->getPointerOperand();
		if(Constant * c = dyn_cast < Constant > (ptr)){
		}else if (ptr->getType()->getTypeID() != Type::VoidTyID) {
			mapValue(insert_point, ptr, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
			if (GetElementPtrInst * GEPI2 = dyn_cast < GetElementPtrInst > (ptr)){
				debug(GEPI2,"#GetElementPtr depends on Pointer(GetElementPtr)#");
				handleGetElementPtrInst(insert_point, GEPI2, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
			}else if (CastInst * CI = dyn_cast < CastInst > (ptr)){
				debug(ptr,"#GetElementPtr depends on Pointer(CastInst):#");
				handleCastInst(insert_point, CI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
			}else if (LoadInst * LI = dyn_cast < LoadInst > (ptr)) {
				debug(ptr,"#GetElementPtr depends on Pointer(LoadInst):#");
				handleLoadInst(insert_point, LI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
			}
		}

	}
}
void AFLCoverage::handleLoadInst(Value *insert_point, LoadInst * LI, GlobalVariable *AFLMapPtr,
		GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
		unsigned int cur_loc) {
	Value * load_address= LI->getPointerOperand();
	if(Constant * c = dyn_cast < Constant > (load_address)){
	}else{
		mapValue(insert_point, load_address, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		if (GetElementPtrInst * GEPI = dyn_cast < GetElementPtrInst > (load_address)){
			debug(GEPI,"#LoadInst depends on GetElementPtr#");
			handleGetElementPtrInst(insert_point, GEPI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		}else if (AllocaInst * AI = dyn_cast < AllocaInst > (load_address)){
			//ignore AllocaInst
		}else{
			debug(load_address,"Unknown load_address:");
		}
	}
}
void AFLCoverage::handleCastInst(Value *insert_point, CastInst * CI, GlobalVariable *AFLMapPtr,
		GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
		unsigned int cur_loc) {
	Value * cast_source= CI->getOperand(0);
	if(Constant * c = dyn_cast < Constant > (cast_source)){
	}else{
		mapValue(insert_point, cast_source, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		if (LoadInst * LI = dyn_cast < LoadInst > (cast_source)) {
			debug(LI,"#CastInst depends on LoadInst#");
			handleLoadInst(insert_point, LI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		}
	}
}
void AFLCoverage::handleFCmpInst(Value *insert_point, FCmpInst * FCmp, GlobalVariable *AFLMapPtr,
		GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
		unsigned int cur_loc) {
	//TODO map float variable
	//Value * op0 = FCmp->getOperand(0);
	//Value * op1 = FCmp->getOperand(1);

}
void AFLCoverage::handleICmpInst(Value *insert_point, ICmpInst * ICmp, GlobalVariable *AFLMapPtr,
		GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
		unsigned int cur_loc) {
	Value * op0 = ICmp->getOperand(0);
	Value * op1 = ICmp->getOperand(1);
	if(Constant * consop0 = dyn_cast < Constant > (op0)){
	}else if (op0->getType()->getTypeID() != Type::VoidTyID) {
		mapValue(insert_point, op0, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		if (CastInst * CI = dyn_cast < CastInst > (op0)) {
			debug(CI,"#[OP0] of ICmpInst is a CastInst#");
			handleCastInst(insert_point, CI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		}else if(LoadInst * LI = dyn_cast < LoadInst > (op0)) {
			debug(LI,"#[OP0] of ICmpInst is a LoadInst#");
			handleLoadInst(insert_point, LI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		}
	}
	if(Constant * consop1 = dyn_cast < Constant > (op1)){
	}else if (op1->getType()->getTypeID() != Type::VoidTyID) {
		mapValue(insert_point, op1, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		if (CastInst * CI = dyn_cast < CastInst > (op1)) {
			debug(CI,"#[OP1] of ICmpInst is a CastInst#");
			handleCastInst(insert_point, CI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		}else if(LoadInst * LI = dyn_cast < LoadInst > (op1)) {
			debug(LI,"#[OP1] of ICmpInst is a LoadInst#");
			handleLoadInst(insert_point, LI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		}
	}
}
void AFLCoverage::handleBinaryOperator(Value *insert_point, BinaryOperator * BOP, GlobalVariable *AFLMapPtr,
		GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
		unsigned int cur_loc) {
	Value * op0 = BOP->getOperand(0);
	Value * op1 = BOP->getOperand(1);
	if(Constant * consop0 = dyn_cast < Constant > (op0)){
	}else if (op0->getType()->getTypeID() != Type::VoidTyID) {
		mapValue(insert_point, op0, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		if (ICmpInst * icmp0 = dyn_cast < ICmpInst > (op0)) {
			debug(icmp0,"#[OP0] of BinaryOperator is a ICmpInst#");
			handleICmpInst(insert_point, icmp0, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		}else if(LoadInst * LI = dyn_cast < LoadInst > (op0)) {
			debug(LI,"#[OP0] of ICmpInst is a LoadInst#");
			handleLoadInst(insert_point, LI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		}
	}
	if(Constant * consop1 = dyn_cast < Constant > (op1)){
	}else if (op1->getType()->getTypeID() != Type::VoidTyID) {
		mapValue(insert_point, op1, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		if (ICmpInst * icmp1 = dyn_cast < ICmpInst > (op1)) {
			debug(icmp1,"#[OP1] of BinaryOperator is a ICmpInst#");
			handleICmpInst(insert_point, icmp1, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		}else if(LoadInst * LI = dyn_cast < LoadInst > (op1)) {
			debug(LI,"#[OP1] of ICmpInst is a LoadInst#");
			handleLoadInst(insert_point, LI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
		}
	}
}



//size_t AFLCoverage::hashName(Value *v) {
//	std::string var_str;
//	llvm::raw_string_ostream rso(var_str);
//	v->print(rso);
//	OKF("#Now we hash var#:%s", var_str.c_str());
//	int pos = var_str.find("=", 0);
//	std::hash < std::string > str_hash;
//	std::string name_str = var_str;
//	if (pos != -1) {
//		name_str = var_str.substr(0, pos);
//	}
//	return (size_t)(str_hash(name_str));
//
//}
void AFLCoverage::mapValue(Value *insert_point, Value *v, GlobalVariable *AFLMapPtr,
		GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
		unsigned int cur_loc) {

	LLVMContext &C = M.getContext();
	//IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
	//IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
	IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
	BasicBlock::iterator IP = BB.getFirstInsertionPt();
	BasicBlock::iterator InsertIP=IP;
    ///debug(v,"Value to store");
    for(int i=0;IP!= BB.end();IP++,i++)
	{
		///std::string info_str;
		///llvm::raw_string_ostream rso(info_str);
		///rso<<"BBInst["<<i<<"]";
		///debug(&(*IP),rso.str());
		if (&(*IP) == insert_point){
			InsertIP = IP;
			break;
		}
	}
	IRBuilder<> IRB(&(*InsertIP));
	//use Int64Ty
	/* Load SHM pointer */

	LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
	MapPtr->setMetadata(M.getMDKindID("nosanitize"),MDNode::get(C, None));
	///debug(MapPtr,"MapPtr\t");
        
#ifdef __x86_64__
	IntegerType *LargestType = Int64Ty;
	ConstantInt *Offset = ConstantInt::get(LargestType, MAP_SIZE +16+(cur_loc<<3));
#else
	IntegerType *LargestType = Int32Ty;
	ConstantInt *Offset = ConstantInt::get(LargestType, MAP_SIZE +16+(cur_loc<<2));
#endif
	
	Value *_MapValuePtr = IRB.CreateGEP(MapPtr, Offset);
	ConstantInt *Zero=ConstantInt::get(LargestType, 0);
	Value *MapValuePtr = IRB.CreateGEP(LargestType, _MapValuePtr, Zero);
	///debug(MapValuePtr,"MapValuePtr\t");

#ifdef LLVM_OLD_DEBUG_API
	LoadInst * pre_v = IRB.CreateLoad(MapValuePtr);
	pre_v->mutateType(LargestType);
#else
	LoadInst * pre_v = IRB.CreateLoad(LargestType,MapValuePtr);
#endif
	pre_v->setMetadata(M.getMDKindID("nosanitize"),MDNode::get(C, None));    
	///debug(pre_v,"pre_v\t");
	Value * casted_v=IRB.CreateZExt(v,LargestType);
	///debug(casted_v,"casted_v\t");
	Value * shled_v=IRB.CreateShl(casted_v,lattice);
	///debug(shled_v,"shled_v\t");
	Value * new_v = IRB.CreateXor(shled_v, pre_v);
	///debug(new_v,"new_v\t");

#ifdef __x86_64__
	lattice=(lattice+8)%64;
#else
	lattice=(lattice+8)%32;
#endif


	StoreInst *myStore = IRB.CreateStore(new_v, MapValuePtr);
	myStore->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
    ///debug(myStore,"myStore\t");

}
bool AFLCoverage::runOnModule(Module &M) {

	bool is_aflgo = false;
	bool is_aflgo_preprocessing = false;

	if (!TargetsFile.empty() && !DistanceFile.empty()) {
		FATAL("Cannot specify both '-targets' and '-distance'!");
		return false;
	}

	std::list < std::string > targets;
	std::map<std::string, int> bb_to_dis;
	std::vector < std::string > basic_blocks;

	if (!TargetsFile.empty()) {

		if (OutDirectory.empty()) {
			FATAL("Provide output directory '-outdir <directory>'");
			return false;
		}

		std::ifstream targetsfile(TargetsFile);
		std::string line;
		while (std::getline(targetsfile, line))
			targets.push_back(line);
		targetsfile.close();

		is_aflgo_preprocessing = true;

	} else if (!DistanceFile.empty()) {
		if (OutDirectory.empty()) {
			FATAL("Provide output directory '-outdir <directory>'");
			FATAL("We need to out put <BBname,RandomID> pairs into <directory>/bbname_rid_pairs.txt");
			FATAL("TIP:<BBname>::=<filename>:<linenum>  e.g 'entry.c:45,1804289383'");
			return false;
		}
		std::ifstream cf(DistanceFile.c_str());
		if (cf.is_open()) {

			std::string line;
			while (getline(cf, line)) {

				std::size_t pos = line.find(",");
				std::string bb_name = line.substr(0, pos);
				int bb_dis = (int) (100.0
						* atof(line.substr(pos + 1, line.length()).c_str()));

				bb_to_dis.insert(std::pair<std::string, int>(bb_name, bb_dis));
				basic_blocks.push_back(bb_name);

			}
			cf.close();

			is_aflgo = true;

		} else {
			FATAL("Unable to find %s.", DistanceFile.c_str());
			return false;
		}

	}

	LLVMContext &C = M.getContext();

	IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
	IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
	IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

	/* Show a banner */

	char be_quiet = 0;

	if (isatty(2) && !getenv("AFL_QUIET")) {

		if (is_aflgo || is_aflgo_preprocessing)
			SAYF(
					cCYA "aflgo-llvm-pass (yeah!) " cBRI VERSION cRST " (%s mode)\n",
					(is_aflgo_preprocessing ?
							"preprocessing" : "distance instrumentation"));
		else
			SAYF(
					cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

	} else
		be_quiet = 1;

	/* Decide instrumentation ratio */

	char* inst_ratio_str = getenv("AFL_INST_RATIO");
	unsigned int inst_ratio = 100;

	if (inst_ratio_str) {

		if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio
				|| inst_ratio > 100)
			FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

	}

	/* Default: Not selecitive */
	char* is_selective_str = getenv("AFLGO_SELECTIVE");
	unsigned int is_selective = 0;

	if (is_selective_str && sscanf(is_selective_str, "%u", &is_selective) != 1)
		FATAL("Bad value of AFLGO_SELECTIVE (must be 0 or 1)");

	char* dinst_ratio_str = getenv("AFLGO_INST_RATIO");
	unsigned int dinst_ratio = 100;

	if (dinst_ratio_str) {

		if (sscanf(dinst_ratio_str, "%u", &dinst_ratio) != 1 || !dinst_ratio
				|| dinst_ratio > 100)
			FATAL("Bad value of AFLGO_INST_RATIO (must be between 1 and 100)");

	}

	/* Get globals for the SHM region and the previous location. Note that
	 __afl_prev_loc is thread-local. */

	GlobalVariable *AFLMapPtr = new GlobalVariable(M,
			PointerType::get(Int8Ty, 0), false, GlobalValue::ExternalLinkage, 0,
			"__afl_area_ptr");

	GlobalVariable *AFLPrevLoc = new GlobalVariable(M, Int32Ty, false,
			GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
			GlobalVariable::GeneralDynamicTLSModel, 0, false);

	/* Instrument all the things! */

	int inst_blocks = 0;

	if (is_aflgo_preprocessing) {

		std::ofstream bbnames;
		std::ofstream bbcalls;
		std::ofstream fnames;
		std::ofstream ftargets;
		struct stat sb;

		bbnames.open(OutDirectory + "/BBnames.txt",
				std::ofstream::out | std::ofstream::app);
		bbcalls.open(OutDirectory + "/BBcalls.txt",
				std::ofstream::out | std::ofstream::app);
		fnames.open(OutDirectory + "/Fnames.txt",
				std::ofstream::out | std::ofstream::app);
		ftargets.open(OutDirectory + "/Ftargets.txt",
				std::ofstream::out | std::ofstream::app);

		/* Create dot-files directory */
		std::string dotfiles(OutDirectory + "/dot-files");
		if (stat(dotfiles.c_str(), &sb) != 0) {
			const int dir_err = mkdir(dotfiles.c_str(),
					S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
			if (-1 == dir_err)
				FATAL("Could not create directory %s.", dotfiles.c_str());
		}

		for (auto &F : M) {

			bool has_BBs = false;
			std::string funcName = F.getName();

			/* Black list of function names */
			std::vector<std::string> blacklist = {"asan.", "llvm.", "sancov.",
				"free"
				"malloc", "calloc", "realloc"};
			for (std::vector<std::string>::size_type i = 0;
					i < blacklist.size(); i++)
				if (!funcName.compare(0, blacklist[i].size(), blacklist[i]))
					continue;

			bool is_target = false;
			for (auto &BB : F) {

				TerminatorInst *TI = BB.getTerminator();
				IRBuilder<> Builder(TI);

				std::string bb_name("");
				std::string filename;
				unsigned line;

				for (auto &I : BB) {
#ifdef LLVM_OLD_DEBUG_API
					DebugLoc Loc = I.getDebugLoc();
					if (!Loc.isUnknown()) {

						DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
						DILocation oDILoc = cDILoc.getOrigLocation();

						line = oDILoc.getLineNumber();
						filename = oDILoc.getFilename().str();

						if (filename.empty()) {
							line = cDILoc.getLineNumber();
							filename = cDILoc.getFilename().str();
						}
#else

					if (DILocation *Loc = I.getDebugLoc()) {
						line = Loc->getLine();
						filename = Loc->getFilename().str();

						if (filename.empty()) {
							DILocation *oDILoc = Loc->getInlinedAt();
							if (oDILoc) {
								line = oDILoc->getLine();
								filename = oDILoc->getFilename().str();
							}
						}

#endif /* LLVM_OLD_DEBUG_API */

						/* Don't worry about external libs */
						std::string Xlibs("/usr/");
						if (filename.empty() || line == 0
								|| !filename.compare(0, Xlibs.size(), Xlibs))
							continue;

						if (bb_name.empty()) {

							std::size_t found = filename.find_last_of("/\\");
							if (found != std::string::npos)
								filename = filename.substr(found + 1);

							bb_name = filename + ":" + std::to_string(line);

						}

						if (!is_target) {
							for (std::list<std::string>::iterator it =
									targets.begin(); it != targets.end();
									++it) {

								std::string target = *it;
								std::size_t found = target.find_last_of("/\\");
								if (found != std::string::npos)
									target = target.substr(found + 1);

								std::size_t pos = target.find_last_of(":");
								std::string target_file = target.substr(0, pos);
								unsigned int target_line = atoi(
										target.substr(pos + 1).c_str());

								if (!target_file.compare(filename)
										&& target_line == line)
									is_target = true;

							}
						}

						if (auto *c = dyn_cast < CallInst > (&I)) {

							std::size_t found = filename.find_last_of("/\\");
							if (found != std::string::npos)
								filename = filename.substr(found + 1);

							if (c->getCalledFunction()) {
								std::string called =
										c->getCalledFunction()->getName().str();

								bool blacklisted = false;
								for (std::vector<std::string>::size_type i = 0;
										i < blacklist.size(); i++) {
									if (!called.compare(0, blacklist[i].size(),
											blacklist[i])) {
										blacklisted = true;
										break;
									}
								}
								if (!blacklisted)
									bbcalls << bb_name << "," << called << "\n";
							}
						}
					}
				}

				if (!bb_name.empty()) {

					BB.setName(bb_name + ":");
					if (!BB.hasName()) {
						std::string newname = bb_name + ":";
						Twine t(newname);
						SmallString < 256 > NameData;
						StringRef NameRef = t.toStringRef(NameData);
						BB.setValueName(ValueName::Create(NameRef));
					}

					bbnames << BB.getName().str() << "\n";
					has_BBs = true;

#ifdef AFLGO_TRACING
					Value *bbnameVal = Builder.CreateGlobalStringPtr(bb_name);
					Type *Args[] = {
						Type::getInt8PtrTy(M.getContext()) //uint8_t* bb_name
					};
					FunctionType *FTy = FunctionType::get(Type::getVoidTy(M.getContext()), Args, false);
					Constant *instrumented = M.getOrInsertFunction("llvm_profiling_call", FTy);
					Builder.CreateCall(instrumented, {bbnameVal});
#endif

				}
			}

			if (has_BBs) {
				/* Print CFG */
				std::string cfgFileName = dotfiles + "/cfg." + funcName
						+ ".dot";
				struct stat buffer;
				if (stat(cfgFileName.c_str(), &buffer) != 0) {
					FILE *cfgFILE = fopen(cfgFileName.c_str(), "w");
					if (cfgFILE) {
						raw_ostream *cfgFile = new llvm::raw_fd_ostream(
								fileno(cfgFILE), false, true);

						WriteGraph(*cfgFile, (const Function*) &F, true);
						fflush(cfgFILE);
						fclose(cfgFILE);
					}
				}
				if (is_target)
					ftargets << F.getName().str() << "\n";
				fnames << F.getName().str() << "\n";
			}
		}

		bbnames.close();
		bbcalls.close();
		fnames.close();
		ftargets.close();

	} else {
		/*add by yangke start*/
		std::ofstream bbname_id_pairs;
		OKF("#Dump <<BBname>,RandomId> pairs to %s",
				(OutDirectory + "/bbname_rid_pairs.txt\n").c_str());
		bbname_id_pairs.open(OutDirectory + "/bbname_rid_pairs.txt",
				std::ofstream::out | std::ofstream::app);

		/*add by yangke end*/
		for (auto &F : M) {

			int distance = -1;

			for (auto &BB : F) {

				distance = -1;

				if (is_aflgo) {
					TerminatorInst *TI = BB.getTerminator();
					IRBuilder<> Builder(TI);

					std::string bb_name;
					for (auto &I : BB) {

#ifdef LLVM_OLD_DEBUG_API
						DebugLoc Loc = I.getDebugLoc();
						if (!Loc.isUnknown()) {

							DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
							DILocation oDILoc = cDILoc.getOrigLocation();

							unsigned line = oDILoc.getLineNumber();
							std::string filename = oDILoc.getFilename().str();

							if (filename.empty()) {
								line = cDILoc.getLineNumber();
								filename = cDILoc.getFilename().str();
							}
#else
						if (DILocation *Loc = I.getDebugLoc()) {

							unsigned line = Loc->getLine();
							std::string filename = Loc->getFilename().str();

							if (filename.empty()) {
								DILocation *oDILoc = Loc->getInlinedAt();
								if (oDILoc) {
									line = oDILoc->getLine();
									filename = oDILoc->getFilename().str();
								}
							}
#endif /* LLVM_OLD_DEBUG_API */

							if (filename.empty() || line == 0)
								continue;
							std::size_t found = filename.find_last_of("/\\");
							if (found != std::string::npos)
								filename = filename.substr(found + 1);

							bb_name = filename + ":" + std::to_string(line);
							break;

						}

					}

					if (!bb_name.empty()) {

						if (find(basic_blocks.begin(), basic_blocks.end(),
								bb_name) == basic_blocks.end()) {

							if (is_selective)
								continue;

						} else {

							/* Find distance for BB */

							if (AFL_R(100) < dinst_ratio) {
								std::map<std::string, int>::iterator it;
								for (it = bb_to_dis.begin();
										it != bb_to_dis.end(); ++it)
									if (it->first.compare(bb_name) == 0)
										distance = it->second;

								/* DEBUG */
								// ACTF("Distance for %s\t: %d", bb_name.c_str(), distance);
							}
						}
					}
				}

				//original aflgo instrumentation start
				BasicBlock::iterator IP = BB.getFirstInsertionPt();
				IRBuilder<> IRB(&(*IP));

				if (AFL_R(100) >= inst_ratio)
					continue;

				/* Make up cur_loc */

				unsigned int cur_loc = AFL_R(MAP_SIZE);

				//original aflgo instrumentation break
				/*add by yangke start*/
				if (!OutDirectory.empty())
					bbRecord(cur_loc, BB, bbname_id_pairs);
				/*add by yangke end*/
				/*add by yangke start*/
#ifndef YANGKE
                if (distance < 0 && AFL_R(4) < 1) //monitor with probability 1/4 if static analysis said that it's not reachable.
                	continue;
				TerminatorInst *TI = BB.getTerminator();
				///OKF("add by yangke.");
				std::string alert_info;
				llvm::raw_string_ostream rso(alert_info);
				TI->print(rso);
				//lattice=0;//reset lattice shl param of value to store for new BB instrumentation
				///OKF("#TerminatorInst#:%s", alert_info.c_str());
				if (BranchInst * BI = dyn_cast < BranchInst > (TI)) {
					if (BI->isConditional()) {
						Value * cond = BI->getCondition();
						if (ICmpInst * icmp = dyn_cast < ICmpInst > (cond)) {
							debug(icmp,"#Condition Value is a ICmpInst#");
							handleICmpInst(cond, icmp, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
							OKF("Instrument[%d] With Condition:ICmpInst OK!\n",instrument_cnt++);
						} else if (FCmpInst * fcmp = dyn_cast < FCmpInst > (cond)) {
							debug(fcmp,"#FCompInst#");
							////FATAL("TODO:Check and fix it!");
							handleFCmpInst(cond, fcmp, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
						} else if (BinaryOperator * BOP = dyn_cast < BinaryOperator > (cond)) {
							debug(BOP,"#Condition Value is a BinaryOperator#");
							handleBinaryOperator(cond, BOP, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
							OKF("--Instrument[%d] With Condition:BinaryOperator OK!\n",instrument_cnt++);
						}
					}
				}else if (SwitchInst * SI = dyn_cast < SwitchInst > (TI)) {
					Value * cond = SI->getCondition();
					if (CastInst * CI = dyn_cast < CastInst > (cond)) {
						debug(CI,"#Condition Value depends on CastInst#");
						handleCastInst(cond, CI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
						OKF("Instrument[%d] With Condition:CastInst in SwitchInst OK!\n",instrument_cnt++);
					}else if (LoadInst * LI = dyn_cast < LoadInst > (cond)) {
						debug(LI,"#Condition Value depends on LoadInst#");
						handleLoadInst(cond, LI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
						OKF("Instrument[%d] With Condition:LoadInst in SwitchInst OK!\n",instrument_cnt++);
					}

					unsigned num=0;

					for(SwitchInst::CaseIt it=SI->case_begin();it!=SI->case_end();it++,num++)
					{

						///OKF("#NUM#:%d",num);
						ConstantInt * value=it.getCaseValue();
						int64_t x=value->getSExtValue();
						debug(value,"#Case Value#");
						OKF("#Case Value#SExt#i32:%d", (int)x);
						//TODO: record and resuse these special data when testing.
					}
				}
#endif
				/*add by yangke end*/
				//original aflgo instrumentation resume
				ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

				/* Load prev_loc */

				LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
				PrevLoc->setMetadata(M.getMDKindID("nosanitize"),
						MDNode::get(C, None));
				Value *PrevLocCasted = IRB.CreateZExt(PrevLoc,
						IRB.getInt32Ty());

				/* Load SHM pointer */

				LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
				MapPtr->setMetadata(M.getMDKindID("nosanitize"),
						MDNode::get(C, None));
				Value *MapPtrIdx = IRB.CreateGEP(MapPtr,
						IRB.CreateXor(PrevLocCasted, CurLoc));

				/* Update bitmap */

				LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
				Counter->setMetadata(M.getMDKindID("nosanitize"),
						MDNode::get(C, None));
				Value *Incr = IRB.CreateAdd(Counter,
						ConstantInt::get(Int8Ty, 1));
				IRB.CreateStore(Incr, MapPtrIdx)->setMetadata(
						M.getMDKindID("nosanitize"), MDNode::get(C, None));

				/* Set prev_loc to cur_loc >> 1 */

				StoreInst *Store = IRB.CreateStore(
						ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
				Store->setMetadata(M.getMDKindID("nosanitize"),
						MDNode::get(C, None));

				if (distance != -1) {

					unsigned int udistance = (unsigned) distance;

#ifdef __x86_64__
					IntegerType *LargestType = Int64Ty;
					ConstantInt *MapDistLoc = ConstantInt::get(LargestType,
							MAP_SIZE);
					ConstantInt *MapCntLoc = ConstantInt::get(LargestType,
							MAP_SIZE + 8);
					ConstantInt *Distance = ConstantInt::get(LargestType,
							udistance);
#else
					IntegerType *LargestType = Int32Ty;
					ConstantInt *MapDistLoc = ConstantInt::get(LargestType,
							MAP_SIZE);
					ConstantInt *MapCntLoc = ConstantInt::get(LargestType,
							MAP_SIZE + 4);
					ConstantInt *Distance = ConstantInt::get(LargestType,
							udistance);
#endif

					/* Add distance to shm[MAPSIZE] */

					Value *MapDistPtr = IRB.CreateGEP(MapPtr, MapDistLoc);
#ifdef LLVM_OLD_DEBUG_API
					LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
					MapDist->mutateType(LargestType);
#else
					LoadInst *MapDist = IRB.CreateLoad(LargestType, MapDistPtr);
#endif
					MapDist->setMetadata(M.getMDKindID("nosanitize"),
							MDNode::get(C, None));
					Value *IncrDist = IRB.CreateAdd(MapDist, Distance);
					IRB.CreateStore(IncrDist, MapDistPtr)->setMetadata(
							M.getMDKindID("nosanitize"), MDNode::get(C, None));

					/* Increase count at to shm[MAPSIZE + (4 or 8)] */

					Value *MapCntPtr = IRB.CreateGEP(MapPtr, MapCntLoc);
#ifdef LLVM_OLD_DEBUG_API
					LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
					MapCnt->mutateType(LargestType);
#else
					LoadInst *MapCnt = IRB.CreateLoad(LargestType, MapCntPtr);
#endif
					MapCnt->setMetadata(M.getMDKindID("nosanitize"),
							MDNode::get(C, None));
					Value *IncrCnt = IRB.CreateAdd(MapCnt,
							ConstantInt::get(LargestType, 1));
					IRB.CreateStore(IncrCnt, MapCntPtr)->setMetadata(
							M.getMDKindID("nosanitize"), MDNode::get(C, None));

				}

				inst_blocks++;

			}
		}
		/*add by yangke start*/
		bbname_id_pairs.close();
		/*add by yangke end*/
	}

	/* Say something nice. */

	if (!is_aflgo_preprocessing && !be_quiet) {

		if (!inst_blocks)
			WARNF("No instrumentation targets found.");
		else
			OKF(
					"Instrumented %u locations (%s mode, ratio %u%%, dist. ratio %u%%).",
					inst_blocks,
					getenv("AFL_HARDEN") ?
							"hardened" :
							((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
									"ASAN/MSAN" : "non-hardened"), inst_ratio,
					dinst_ratio);

	}

	return true;

}

static void registerAFLPass(const PassManagerBuilder &,
		legacy::PassManagerBase &PM) {

	PM.add(new AFLCoverage());

}

static RegisterStandardPasses RegisterAFLPass(
		PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
		PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
