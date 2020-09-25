#!/usr/bin/env python

import argparse
import os
import re
import subprocess
import warnings 
# Main function
if __name__ == '__main__':

  parser = argparse.ArgumentParser ()
  parser.add_argument ('-p', '--program', type=str, required=True, help="The program")
  parser.add_argument ('-q', '--crash_dir', type=str, required=True, help="The crash dir")
  args = parser.parse_args ()
  print "\nPROGRAM: %s" % args.program
  print "\nOUT_DIR: %s" % args.crash_dir

  path=args.crash_dir
  abort=0;
  segfault=0
  not_trigger=0;
  min_d=2<<31
  li=[]
  filearray=[]
  for fname in os.listdir(path):
      if fname==".state" or "orig:" in fname :continue
      array=fname.split(",")
      if len(array)==1: continue
      t=int(array[1])
      d=array[2]
      li.append((t,d,fname))
  li.sort()

  for t,d,fname in li:
      dis=float(d)
      if min_d>dis and dis >0:
          min_d=dis
      if args.program=="NULL":
          print t,d,min_d
          continue
      print fname
      cmd=args.program + " <" +args.crash_dir+ "/" + fname
      p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
      out, err = p.communicate()
      code = p.returncode
      if code==0:
          not_trigger+=1
      elif code==139:#Segment fault
          segfault+=1
      elif code==124:#Abort
          abort+=1
          
          
  #print "Trigger %d" % trigger
  #print "Not trigger %d" % not_trigger
