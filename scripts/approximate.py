#! /usr/bin/env python
'''
This script help find the key bytes that change a benign file to crash
./approximate.py -a ./in/seed.jpg -b ./out/target_result/crashes/crashfile'./jdmarker_profiled @@'

'''
import argparse
import os
import re
import subprocess
import warnings
import sys

def read_into_buffer(filename):
	buf = bytearray(os.path.getsize(filename))
	with open(filename, 'rb') as f:
		f.readinto(buf)
	return buf
def show(m,temp,seed):
	for i in range(len(m)):
		if i%16==0:print "\n"
		if m[i]==0:
                    print "%2x" % temp[i],
                else:
                    print "%2x/\033[32m%2x\033[0m" % (seed[i],temp[i]),
def approximate(benign_input,crash_input,output,cmd):
	m=[]
	seed=read_into_buffer(benign_input)
	crash=read_into_buffer(crash_input)
	temp=crash
        if len(crash) < len(seed):
		temp=crash+seed[len(crash):]
		with open(output, 'wb') as ftest:
			ftest.write(temp)
		ftest.close()
		rt=os.system(cmd.replace('@@',output))
		if rt==0:
			with open('./crashes/log', 'w') as ftest:
				ftest.write("Chopped to the length of crash input, otherwise it will not trigger crash")
			ftest.close()
			temp=crash
	
	for i in range(len(temp)):
		if temp[i]!=seed[i]:
			x=temp[i]
			temp[i]=seed[i]
			with open(output, 'wb') as ftest:
				ftest.write(temp)
			ftest.close()
			rt=os.system(cmd.replace('@@',output))
			if rt==0:
				temp[i]=x
				m.append(1)
			else:
				m.append(0)
		else:m.append(0)

	show(m,temp,seed)


# Main function
if __name__ == '__main__':

  parser = argparse.ArgumentParser ()
  parser.add_argument ('-a', '--benign_input', type=str, required=True, help="Benign input")
  parser.add_argument ('-b', '--crash_input', type=str, required=True, help="Crash input")
  parser.add_argument ('-o', '--output', type=str, required=True, help="Approximated crash file")
  parser.add_argument ('-c', '--command', type=str, required=True, help="Command e.g. './jdmarker_profiled @@' '@@' is the place holder for input file")

  args = parser.parse_args ()
  approximate(args.benign_input,args.crash_input,args.output,args.command)
  

