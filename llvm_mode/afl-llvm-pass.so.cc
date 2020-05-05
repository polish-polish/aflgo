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
	static unsigned bb_cnt;
	/* add by yangke end */
	AFLCoverage() :
			ModulePass(ID) {
	}

	bool runOnModule(Module &M) override;
protected:
	void mapValue(Value *insert_point, Value *v, GlobalVariable *AFLMapPtr,
			GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
			unsigned int cur_loc);
	void mapValue2(Value *insert_point, Value *v, Value *v1, GlobalVariable *AFLMapPtr,
				GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
				unsigned int cur_loc);
	size_t hashName(Value *v);
	void debug(Value *v,std::string info="#Value#--");
	std::string getBBName(BasicBlock &BB);
	std::string bbRecord(unsigned int cur_loc, BasicBlock &BB, std::ofstream &bbname_id_pairs);

	std::string getAnswerICmp(ICmpInst * ICmp);
	std::string getAnswerSwitch(SwitchInst * SI, std::map<std::string, int> bb_to_dis, std::vector < std::string > basic_blocks);
	void bbBranchRecord(std::string key_str,BasicBlock &BB, std::ofstream &bb_branch_info, std::map<std::string, int> bb_to_dis, std::vector < std::string > basic_blocks);

	int handleStrCmp(ICmpInst *ICmp, GlobalVariable *AFLMapPtr,
			GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
			unsigned int cur_loc);

	StringRef getStringInStrCmp(ICmpInst *ICmp);

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
	void InstrumentBB(Value *insert_point, GlobalVariable *AFLMapPtr,
				GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
				unsigned int cur_loc);
};

}

char AFLCoverage::ID = 0;
/* add by yangke start */
unsigned AFLCoverage::instrument_cnt = 0;
unsigned AFLCoverage::bb_cnt = 0;
unsigned AFLCoverage::lattice = 0;//shr step
/* add by yangke end */
/* Record the basic block informatio and return the its id_str
 * The id_str is a star graph that construct of all path of:[pred_pred_pred]->[pred_pred]->[pred]->[it]->[succ]
 * e.g. pred1{pred_pred1(pred_pred_pred1&pred_pred_pred2)#pred_pred2(...)},pred2{...};succ1,succ2
 * And "pred" "it" et al in this expression is the debugging string of the corresponding BasicBlock
 * which is debugging information of the first Instruction get by BB.getFirstInsertionPt().
 * e.g. jdmarker.c:601:32
 * */
std::string AFLCoverage::bbRecord(unsigned int cur_loc, BasicBlock &BB,
		std::ofstream &bbname_id_pairs) {
	std::string id_str="";
	std::string loc_str="";
	std::string bb_cnt_str="";
	std::stringstream ss;
	ss<<cur_loc;
	ss>>loc_str;
	ss.clear();
	//OKF("%d",bb_cnt);
	ss<<bb_cnt;
	ss>>bb_cnt_str;
	//id_str=";";
	id_str=getBBName(BB)+";";
	for (auto pit = pred_begin(&BB), pet = pred_end(&BB); pit != pet; ++pit)
	{
		BasicBlock* predecessor = *pit;
		if (id_str[id_str.size()-1]==';'){
			id_str+= getBBName(*predecessor);
		}else{
			id_str+= ","+getBBName(*predecessor);
		}
		id_str+= "{";
		for (auto pit2 = pred_begin(predecessor), pet2 = pred_end(predecessor); pit2 != pet2; ++pit2)
		{
			BasicBlock* pred_pred = *pit2;
			if (id_str[id_str.size()-1]=='{'){
				id_str+=getBBName(*pred_pred);
			}else{
				id_str+="#"+getBBName(*pred_pred);
			}
			id_str+="(";
			for (auto pit3 = pred_begin(pred_pred), pet3 = pred_end(pred_pred); pit3 != pet3; ++pit3)
			{
				BasicBlock* pred_pred_pred = *pit3;
				if (id_str[id_str.size()-1]=='('){
					id_str+=getBBName(*pred_pred_pred);
				}else{
					id_str+="&"+getBBName(*pred_pred_pred);
				}
			}
			if (id_str[id_str.size()-1]=='('){
				id_str=id_str.substr(0,id_str.size()-1);
			}else{
				id_str+= ")";
			}
		}
		if (id_str[id_str.size()-1]=='{'){
			id_str=id_str.substr(0,id_str.size()-1);
		}else{
			id_str+= "}";
		}
	}
	id_str+=";";
	TerminatorInst *TI = BB.getTerminator();
	for (auto *sit : TI->successors())//for (BasicBlock *Succ : TI->successors())
	{
		if(id_str[id_str.size()-1]==';'){
			id_str+= getBBName(*sit);
		}else{
			id_str+="," + getBBName(*sit);
		}
	}
	bbname_id_pairs <<bb_cnt_str+";"+loc_str+";"+id_str<<"\n";
	return id_str;
}
int getDistance(std::string bb_name,std::map<std::string, int> bb_to_dis, std::vector < std::string > basic_blocks){
	int d=-1;
	if (!bb_name.empty()) {
		if (find(basic_blocks.begin(), basic_blocks.end(),
				bb_name) == basic_blocks.end()) {

			WARNF("Cannnot find bb_name: %s in distance.cfg.txt! Set it to -1",bb_name.c_str());

		} else {

			/* Get distance for BB */
			std::map<std::string, int>::iterator it=bb_to_dis.find(bb_name);
			if(it!= bb_to_dis.end()){
				d = it->second;
			}
//			std::map<std::string, int>::iterator it;
//			for (it = bb_to_dis.begin();
//					it != bb_to_dis.end(); ++it)
//				if (it->first.compare(bb_name) == 0)
//					d = it->second;
		}
	}
	return d;
}
std::string AFLCoverage::getAnswerICmp(ICmpInst * ICmp){
	Value * op0 = ICmp->getOperand(0);
	Value * op1 = ICmp->getOperand(1);
	ConstantInt * consop0 = dyn_cast < ConstantInt > (op0);
	ConstantInt * consop1 = dyn_cast < ConstantInt > (op1);
	StringRef sr= getStringInStrCmp(ICmp);
	if(StringRef("").compare(sr)){
		return "\""+sr.str()+"\"";
	}
	std::string result="";
	std::stringstream ss;
	if((!consop0)&&consop1){
		ss<<consop1->getZExtValue();
	}else if(consop0&&(!consop1)){
		ss<<consop0->getZExtValue();
	}
	ss>>result;
	return result;
}
std::string AFLCoverage::getAnswerSwitch(SwitchInst * SI, std::map<std::string, int> bb_to_dis, std::vector < std::string > basic_blocks){
	std::stringstream ss;
	std::string result="";
	unsigned idx=0;
	for(SwitchInst::CaseIt it=SI->case_begin();it!=SI->case_end();it++,idx++)
	{
		ConstantInt * value=it.getCaseValue();
		BasicBlock * succesor=it.getCaseSuccessor();
		std::string bn=getBBName(*succesor);
		if(idx!=0) ss<<",";
		ss<<value->getZExtValue()<<":"<<getDistance(bn,bb_to_dis,basic_blocks);
	}
	ss>>result;
	return result;
}

void AFLCoverage::bbBranchRecord(std::string key_str,BasicBlock &BB, std::ofstream &bb_branch_info, std::map<std::string, int> bb_to_dis, std::vector < std::string > basic_blocks){
	std::string info="";
	TerminatorInst *TI = BB.getTerminator();
	if (BranchInst * BI = dyn_cast < BranchInst > (TI)) {
		if (BI->isConditional()) {
			Value * cond = BI->getCondition();
			if (ICmpInst * icmp = dyn_cast < ICmpInst > (cond)){
				info=getAnswerICmp(icmp);
			}else if (BinaryOperator * BOP = dyn_cast < BinaryOperator > (cond)) {
				//TODO:info=getAnswerBinaryOperator(id_str,icmp,bb_branch_info);
			}
		}
	}else if (SwitchInst * SI = dyn_cast < SwitchInst > (TI)) {
		info=getAnswerSwitch(SI,bb_to_dis, basic_blocks);
	}
	if(info.length()>0){
		bb_branch_info<<bb_cnt<<"|"+info<<"|"<<key_str+"\n";
	}
}
std::string AFLCoverage::getBBName(BasicBlock &BB) {
	std::string bb_name("");
	std::string filename;
	unsigned line,column;
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
			column = Loc->getColumn();
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

				bb_name = filename + ":" + std::to_string(line) + ":" +std::to_string(column);
				return bb_name;
				//break;
			}
		}
	}

	if (bb_name.size()>0){
		return bb_name;
	}else{
		/*std::string Str;
		raw_string_ostream OS(Str);

		BB.printAsOperand(OS, false);
		return OS.str();*/
		return "@";
	}
}
inline void AFLCoverage::debug(Value *v,std::string info) { //contains format string vulnerability
#ifndef DEBUG_
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
	//FATAL("UNHANDLE FCmpInst");
	//TODO map float variable
	//Value * op0 = FCmp->getOperand(0);
	//Value * op1 = FCmp->getOperand(1);

}
StringRef AFLCoverage::getStringInStrCmp(ICmpInst *ICmp) {
	if(ICmpInst::ICMP_EQ==ICmp->getPredicate()||ICmpInst::ICMP_NE==ICmp->getPredicate())
	{
		Value * op0 = ICmp->getOperand(0);
		Value * op1 = ICmp->getOperand(1);
		ConstantInt * c0 = dyn_cast < ConstantInt > (op0);
		ConstantInt * c1 = dyn_cast < ConstantInt > (op1);
		Value *op=NULL;
		if(!c0 && c1 && c1->getZExtValue()==0){
			op=op0;
		}else if(!c1 && c0 && c0->getZExtValue()==0){
			op=op1;
		}
		if(op){
			if(CallInst * CI = dyn_cast < CallInst > (op)){
				Function *func = CI->getCalledFunction();
				if (func && 0==func->getName().compare(StringRef("strcmp"))){
					Value * arg0=CI->getArgOperand(0);
					Value * arg1=CI->getArgOperand(1);
					ConstantExpr  * const_expr0 = dyn_cast < ConstantExpr > (arg0);
					ConstantExpr  * const_expr1 = dyn_cast < ConstantExpr > (arg1);
					ConstantExpr  * const_expr=NULL;
					if(const_expr0&&!const_expr1){
						const_expr=const_expr0;
					}else if(const_expr1&&!const_expr0){
						const_expr=const_expr1;
					}
					if(const_expr){
						Instruction * inst_expr=const_expr->getAsInstruction();
						if(GetElementPtrInst  * CIST = dyn_cast < GetElementPtrInst > (inst_expr)){
							Value * const_str=CIST->getPointerOperand();
							if (GlobalVariable *GV = dyn_cast<GlobalVariable>(const_str)){
								Constant *v = GV->getInitializer();
								if (ConstantDataArray *CA = dyn_cast<ConstantDataArray>(v)) {
									if(CA->isCString()){
										return CA->getAsCString();
									}
								}
							}
						}
					}
				}//else it is a indirect call
			}
		}
	}
	return StringRef("");
}
int AFLCoverage::handleStrCmp(ICmpInst *ICmp, GlobalVariable *AFLMapPtr,
		GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
		unsigned int cur_loc) {
	Value * op0 = ICmp->getOperand(0);
	Value * op1 = ICmp->getOperand(1);
	ConstantInt * c0 = dyn_cast < ConstantInt > (op0);
	ConstantInt * c1 = dyn_cast < ConstantInt > (op1);
	Value *op=NULL;
	if(!c0 && c1 && c1->getZExtValue()==0){
		op=op0;
	}else if(!c1 && c0 && c0->getZExtValue()==0){
		op=op1;
	}
	if(op){
		if(CallInst * CI = dyn_cast < CallInst > (op)){
			Function *func = CI->getCalledFunction();
			if (func && 0==func->getName().compare(StringRef("strcmp"))){
				Value * arg0=CI->getArgOperand(0);
				Value * arg1=CI->getArgOperand(1);
				ConstantExpr  * const_expr0 = dyn_cast < ConstantExpr > (arg0);
				ConstantExpr  * const_expr1 = dyn_cast < ConstantExpr > (arg1);
				GetElementPtrInst  * GEPI=NULL;
				if(const_expr0&&!const_expr1){
					GEPI = dyn_cast < GetElementPtrInst > (arg1);
				}else if(const_expr1&&!const_expr0){
					GEPI = dyn_cast < GetElementPtrInst > (arg0);
				}
				if(GEPI){
					GEPI->getPointerOperand();
					//accumulate all the Char!='\0' to the target memory
				}
			}
		}
	}
	return 0;
}
void AFLCoverage::handleICmpInst(Value *insert_point, ICmpInst * ICmp, GlobalVariable *AFLMapPtr,
		GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
		unsigned int cur_loc) {

	Value * op0 = ICmp->getOperand(0);
	Value * op1 = ICmp->getOperand(1);

	Constant * consop0 = dyn_cast < Constant > (op0);
	Constant * consop1 = dyn_cast < Constant > (op1);


	if(handleStrCmp(ICmp, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc)){

	}else if((!consop0)&&consop1){
		mapValue2(insert_point, op0, op1, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
	}else if(consop0&&(!consop1)){
		mapValue2(insert_point, op1, op0, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
	}else{
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
void AFLCoverage::InstrumentBB(Value *insert_point, GlobalVariable *AFLMapPtr,
	GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M, unsigned int cur_loc) {
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
			if(!insert_point) insert_point=cond;
			if (ICmpInst * icmp = dyn_cast < ICmpInst > (cond)) {
				debug(icmp,"#Condition Value is a ICmpInst#");OKF("rid:%d",cur_loc);
				handleICmpInst(insert_point, icmp, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
				//OKF("Instrument[%d] With Condition:ICmpInst OK!\n",instrument_cnt++);
			} else if (FCmpInst * fcmp = dyn_cast < FCmpInst > (cond)) {
				debug(fcmp,"#FCompInst#");
				////FATAL("TODO:Check and fix it!");
				handleFCmpInst(insert_point, fcmp, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
			} else if (BinaryOperator * BOP = dyn_cast < BinaryOperator > (cond)) {
				debug(BOP,"#Condition Value is a BinaryOperator#");
				handleBinaryOperator(insert_point, BOP, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
				//OKF("--Instrument[%d] With Condition:BinaryOperator OK!\n",instrument_cnt++);
			}
		}
	}else if (SwitchInst * SI = dyn_cast < SwitchInst > (TI)) {
		Value * cond = SI->getCondition();
		debug(SI,"#SwitchInst#");
		if(!insert_point) insert_point=SI;
		mapValue(insert_point, cond, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
//		if (CastInst * CI = dyn_cast < CastInst > (cond)) {
//			debug(CI,"#Condition Value depends on CastInst#");
//			handleCastInst(insert_point, CI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
//			//OKF("Instrument[%d] With Condition:CastInst in SwitchInst OK!\n",instrument_cnt++);
//		}else if (LoadInst * LI = dyn_cast < LoadInst > (cond)) {
//			debug(LI,"#Condition Value depends on LoadInst#");
//			handleLoadInst(insert_point, LI, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
//			//OKF("Instrument[%d] With Condition:LoadInst in SwitchInst OK!\n",instrument_cnt++);
//		}
//
		unsigned idx=0;

		for(SwitchInst::CaseIt it=SI->case_begin();it!=SI->case_end();it++,idx++)
		{

			///OKF("#NUM#:%d",num);
			ConstantInt * value=it.getCaseValue();
			BasicBlock * succesor=SI->getSuccessor(idx);
			std::string bn=getBBName(*succesor);
			//int64_t x=value->getSExtValue();
			debug(value,"#Case Value#");
			//OKF("#Case Value#SExt#i32:%d", (int)x);
			//TODO: record and resuse these special data when testing.
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
	int flag=1;
    for(int i=0;IP!= BB.end();IP++,i++)
	{
		///std::string info_str;
		///llvm::raw_string_ostream rso(info_str);
		///rso<<"BBInst["<<i<<"]";
		///debug(&(*IP),rso.str());
		if (&(*IP) == insert_point){
			InsertIP = IP;flag=0;
			break;
		}
	}
    //IRBuilder<> IRB(&(*InsertIP));
    IRBuilder<> IRB((Instruction *)insert_point);
	//use Int64Ty
	/* Load SHM pointer */

	LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
	MapPtr->setMetadata(M.getMDKindID("nosanitize"),MDNode::get(C, None));
	if(flag)
	debug(MapPtr,"MapPtr\t");
        
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
	if(flag)debug(MapValuePtr,"MapValuePtr\t");

#ifdef LLVM_OLD_DEBUG_API
	LoadInst * pre_v = IRB.CreateLoad(MapValuePtr);
	pre_v->mutateType(LargestType);
#else
	LoadInst * pre_v = IRB.CreateLoad(LargestType,MapValuePtr);
#endif
	pre_v->setMetadata(M.getMDKindID("nosanitize"),MDNode::get(C, None));    
	debug(pre_v,"pre_v\t");
	//Value * shled_prev=IRB.CreateShl(pre_v,ConstantInt::get(LargestType, 1));
	//Value * casted_v=IRB.CreateZExt(v,LargestType);
	//debug(casted_v,"casted_v\t");

	//Value * shled_v=IRB.CreateShl(casted_v,lattice);
	//if(flag)debug(shled_v,"shled_v\t");
	//Value * new_v = IRB.CreateXor(shled_v, pre_v);
	//Value * new_v = IRB.CreateXor(casted_v,shled_prev);
	//debug(new_v,"new_v\t");

#ifdef __x86_64__
	lattice=(lattice+8)%64;
#else
	lattice=(lattice+8)%32;
#endif

	StoreInst *myStore = IRB.CreateStore(v, MapValuePtr);//ConstantInt::get(LargestType, instrument_cnt)
	myStore->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
	debug(myStore,"myStore\t");

}
void AFLCoverage::mapValue2(Value *insert_point, Value *v,Value *v1, GlobalVariable *AFLMapPtr,
		GlobalVariable *AFLPrevLoc, BasicBlock & BB, Module &M,
		unsigned int cur_loc) {

	LLVMContext &C = M.getContext();
	//IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
	IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
	IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
	BasicBlock::iterator IP = BB.getFirstInsertionPt();
	BasicBlock::iterator InsertIP=IP;
    ///debug(v,"Value to store");
	int flag=1;
    for(int i=0;IP!= BB.end();IP++,i++)
	{
		///std::string info_str;
		///llvm::raw_string_ostream rso(info_str);
		///rso<<"BBInst["<<i<<"]";
		///debug(&(*IP),rso.str());
		if (&(*IP) == insert_point){
			InsertIP = IP;flag=0;
			break;
		}
	}
    //IRBuilder<> IRB(&(*InsertIP));
    IRBuilder<> IRB((Instruction *)insert_point);
	//use Int64Ty
	/* Load SHM pointer */

	LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
	MapPtr->setMetadata(M.getMDKindID("nosanitize"),MDNode::get(C, None));
	if(flag)
	debug(MapPtr,"MapPtr\t");

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
	if(flag)debug(MapValuePtr,"MapValuePtr\t");

#ifdef LLVM_OLD_DEBUG_API
	LoadInst * pre_v = IRB.CreateLoad(MapValuePtr);
	pre_v->mutateType(LargestType);
#else
	LoadInst * pre_v = IRB.CreateLoad(LargestType,MapValuePtr);
#endif
	pre_v->setMetadata(M.getMDKindID("nosanitize"),MDNode::get(C, None));
	debug(pre_v,"pre_v\t");

	Value * casted_v=IRB.CreateZExt(v,LargestType);
	Value * casted_v1=IRB.CreateZExt(v1,LargestType);
	Value * sub=IRB.CreateSub(casted_v1,casted_v);


	StoreInst *myStore = IRB.CreateStore(sub, MapValuePtr);//ConstantInt::get(LargestType, instrument_cnt)
	myStore->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
	debug(myStore,"myStore\t");

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
	std::map<std::string, int> func_to_dis;
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
			FATAL("Please provide output directory '-outdir <directory>'\n");
			FATAL("We need to output <BBname,RandomID> pairs into <directory>/rid_bbname_pairs/<func_name>.rid_bbname_pairs.txt");
			FATAL("We need to output branch info into <directory>/bb_branch_info/<func_name>.bb_branch_info.txt");
			FATAL("TIP:<BBname>::=<file name>:<line num>:<column num>  e.g 'entry.c:45:11'");
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
		std::string DistanceCallgraphFile=OutDirectory + "/distance.callgraph.txt";
		std::ifstream dcf(DistanceCallgraphFile);
		if (dcf.is_open()) {

			std::string line;
			while (getline(dcf, line)) {

				std::size_t pos = line.find(",");
				std::string func_name = line.substr(0, pos);
				int func_dis = (int) (100.0
						* atof(line.substr(pos + 1, line.length()).c_str()));

				func_to_dis.insert(std::pair<std::string, int>(func_name, func_dis));

			}
			dcf.close();

			is_aflgo = true;

		} else {
			FATAL("Unable to find %s.", DistanceCallgraphFile.c_str());
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
				unsigned line,column;

				for (auto &I : BB) {
#ifdef LLVM_OLD_DEBUG_API
					DebugLoc Loc = I.getDebugLoc();
					if (!Loc.isUnknown()) {

						DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
						DILocation oDILoc = cDILoc.getOrigLocation();

						line = oDILoc.getLineNumber();
						column = oDILoc.getColumnNumber();
						filename = oDILoc.getFilename().str();

						if (filename.empty()) {
							line = cDILoc.getLineNumber();
							filename = cDILoc.getFilename().str();
						}
#else

					if (DILocation *Loc = I.getDebugLoc()) {
						line = Loc->getLine();
						column = Loc->getColumn();
						filename = Loc->getFilename().str();

						if (filename.empty()) {
							DILocation *oDILoc = Loc->getInlinedAt();
							if (oDILoc) {
								line = oDILoc->getLine();
								column = oDILoc->getColumn();
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

							bb_name = filename + ":" + std::to_string(line) + ":" + std::to_string(column);

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

		for (auto &F : M) {

			/*add by yangke start*/
			/* Create rid_bbname_pairs directory */

			if(OutDirectory.empty()){
				WARNF("OutDirectory is empty!");
			}
			std::ofstream bbname_id_pairs;
			std::string rid_bbname_pairs_dir(OutDirectory + "/rid_bbname_pairs");
			struct stat sb;
			if (stat(rid_bbname_pairs_dir.c_str(), &sb) != 0) {
				const int dir_err = mkdir(rid_bbname_pairs_dir.c_str(),
						S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
				if (-1 == dir_err)
					WARNF("Could not create directory %s.", rid_bbname_pairs_dir.c_str());
			}
			if(!OutDirectory.empty()){
				//M.getSourceFileName()
				OKF("#Dump <<BBname>,RandomId> pairs to %s",
					(rid_bbname_pairs_dir + "/" + F.getName().str() +".rid_bbname_pairs.txt\n").c_str());
				bbname_id_pairs.open(rid_bbname_pairs_dir + "/" + F.getName().str() +".rid_bbname_pairs.txt",
									std::ofstream::out);
				bbname_id_pairs.close();
				bbname_id_pairs.open(rid_bbname_pairs_dir + "/" + F.getName().str() +".rid_bbname_pairs.txt",
					std::ofstream::out | std::ofstream::app);
			}


			/* Create bb_branch_info directory */
			std::ofstream bb_branch_info;
			std::string bb_branch_info_dir(OutDirectory + "/bb_branch_info");

			if (stat(bb_branch_info_dir.c_str(), &sb) != 0) {
				const int dir_err = mkdir(bb_branch_info_dir.c_str(),
						S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
				if (-1 == dir_err)
					WARNF("Could not create directory %s.", bb_branch_info_dir.c_str());
			}
			if(!OutDirectory.empty()){
				//M.getSourceFileName()
				if(func_to_dis.find(F.getName())!=func_to_dis.end())
				{
					OKF("#Dump branch info to %s",
						(bb_branch_info_dir + "/" + F.getName().str() +".bb_branch_info.txt\n").c_str());
					bb_branch_info.open(bb_branch_info_dir + "/" + F.getName().str() +".bb_branch_info.txt",
											std::ofstream::out);
					bb_branch_info.close();
					bb_branch_info.open(bb_branch_info_dir + "/" + F.getName().str() +".bb_branch_info.txt",
						std::ofstream::out | std::ofstream::app);
				}
			}


			/*add by yangke end*/

			int distance = -1;

			for (auto &BB : F) {

				distance = -1;
				std::string bb_name;

				if (is_aflgo) {
					TerminatorInst *TI = BB.getTerminator();
					IRBuilder<> Builder(TI);

					//std::string bb_name;
					for (auto &I : BB) {

#ifdef LLVM_OLD_DEBUG_API
						DebugLoc Loc = I.getDebugLoc();
						if (!Loc.isUnknown()) {

							DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
							DILocation oDILoc = cDILoc.getOrigLocation();

							unsigned line = oDILoc.getLineNumber();
							unsigned column = oDILoc.getColumnNumber();
							std::string filename = oDILoc.getFilename().str();

							if (filename.empty()) {
								line = cDILoc.getLineNumber();
								filename = cDILoc.getFilename().str();
							}
#else
						if (DILocation *Loc = I.getDebugLoc()) {

							unsigned line = Loc->getLine();
							unsigned column = Loc->getColumn();
							std::string filename = Loc->getFilename().str();

							if (filename.empty()) {
								DILocation *oDILoc = Loc->getInlinedAt();
								if (oDILoc) {
									line = oDILoc->getLine();
									column = oDILoc->getColumn();
									filename = oDILoc->getFilename().str();
								}
							}
#endif /* LLVM_OLD_DEBUG_API */

							if (filename.empty() || line == 0)
								continue;
							std::size_t found = filename.find_last_of("/\\");
							if (found != std::string::npos)
								filename = filename.substr(found + 1);

							bb_name = filename + ":" + std::to_string(line) + ":" + std::to_string(column);
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
				if (!OutDirectory.empty()){
					std::string key_str=bbRecord(cur_loc, BB, bbname_id_pairs);
					if (bb_branch_info.is_open()){
						bbBranchRecord(key_str, BB, bb_branch_info, bb_to_dis, basic_blocks);
					}
					bb_cnt++;
				}
#ifndef YANGKE
                if (distance >= 0){
                	if(getBBName(BB).find("jdmarker.c:645:7")!=std::string::npos){
                		WARNF("jdmarker.c:645:7,rid=%d",cur_loc);
                	}

                	if(getBBName(BB).find("jdmarker.c:654:13")!=std::string::npos){
                	    WARNF("jdmarker.c:654:13,rid=%d",cur_loc);
                	}

                	InstrumentBB(NULL, AFLMapPtr, AFLPrevLoc, BB, M, cur_loc);
                }

                //Value *insert_point;

#endif
				/*add by yangke end*/

				//original aflgo instrumentation continue
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
			/*add by yangke start*/
			bbname_id_pairs.close();
			bb_branch_info.close();
			/*add by yangke end*/
		}
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
