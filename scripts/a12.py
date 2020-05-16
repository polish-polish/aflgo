#!/usr/bin/env python
import argparse
import os
import warnings 
class Rx:
  "has the nums of a treatment, its name and rank"
  def __init__(i,lst):
     i.rx, i.lst = lst[0], lst[1:]
     i.mean = sum(i.lst)/len(i.lst)
     i.rank = 0
  def __repr__(i):
    return 'rank #%s %s at %s'%(i.rank,i.rx,i.mean) 

def a12s(lst,rev=True,enough=0.66):
  "sees if lst[i+1] has rank higher than lst[i]"
  lst = [Rx(one) for one in lst]
  lst = sorted(lst,key=lambda x:x.mean,reverse=rev)
  one   = lst[0]
  rank = one.rank = 1
  for two in lst[1:]:
    if a12(one.lst,two.lst,rev) > enough: rank += 1
    two.rank = rank
    one = two
  return lst

def a12(lst1,lst2,rev=True):
  "how often is x in lst1 more than y in lst2?"
  more = same = 0.0
  for x in lst1:
    for y in lst2:
      if   x==y : same += 1
      elif rev     and x > y : more += 1
      elif not rev and x < y : more += 1
  return (more + 0.5*same)  / (len(lst1)*len(lst2))

def fromFile(f="a12.dat",rev=True,enough=0.66):
  "utility for reading sample data from disk"
  import re
  cache = {} 
  num, space = r'^\+?-?[0-9]', r'[ \t\n]+'
  for line in open(f): 
    line = line.strip()
    if line:
      for word in re.split(space,line):
        if re.match(num,word[0]):
          cache[now] += [float(word)]
        else:
          now  = word
          cache[now] = [now]
  return a12s(cache.values(),rev,enough)
# Main function
if __name__ == '__main__':
  parser = argparse.ArgumentParser ()
  parser.add_argument ('-f', '--file', type=str, required=True, help="The file which contains two data list, split by '====' ")
  args = parser.parse_args ()
  print "\nParsing %s .." % args.file
  f=open(args.file, "r")
  lines=f.readlines();
  X=[]#X=['X1']
  Y=[]#Y=['X2']
  is_x=1;
  for s in lines:
     if "=" not in s and is_x==1:
	X.append(float(s))
     elif "=" in s:
        is_x=0
     else:
        Y.append(float(s));
  #rxs=[X,Y]
  #for rx in a12s(rxs,rev=False,enough=0.75): print rx
  print a12(X,Y,0)
  
     
