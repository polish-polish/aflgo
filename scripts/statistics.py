#!/usr/bin/env python

import argparse
import os
import warnings 
# Main function
if __name__ == '__main__':

  parser = argparse.ArgumentParser ()
  parser.add_argument ('-d', '--dir', type=str, required=True, help="The output directory of AFL")
  parser.add_argument ('-n', '--number', type=str, required=True, help="number of results")
  args = parser.parse_args ()
  print "\nParsing %s .." % args.dir
  #GG=merge_all_cfg()
  #nx.drawing.nx_pydot.write_dot(GG, args.temp_dir+"/merge_all_cfg.dot")
  keys=["sddwddddsddw","sddwddddssssddwwww","ssssddddwwaawwddddsddw","ssssddddwwaawwddddssssddwwww"]
  ds=dict()
  for key in keys:
    ds[key]=[]
  cnt=0
  times=int(args.number)
  for i in range(times):
      path=args.dir+'/maze_'+str(i+1)+'_result/crashes'
      temp=cnt
      for fname in os.listdir(path):
          if 'id' in fname:
              t=fname.split(',')[1].strip()
              #cmd='/home/yangke/Program/AFL/aflgo/bak/aflgo-good/afl-showmap -o '+path+'/'+fname+'.bitmap -- /home/yangke/Program/AFL/aflgo/bak/aflgo-good/tutorial/samples/test/maze_profiled '+path+'/'+fname
              #os.system(cmd)
              f=open(path+'/'+fname,'r')
              d=f.read();
              f.close()
              findit=0
              for key in keys:
                 if key in d:
	             ds[key].append(int(t))
                     findit=1
              if findit:
                 cnt+=1
      if temp==cnt:
           print "Cannot find any results in result:"+i,
  statistics=[]
  for key,value in ds.items():
       if len(ds[key])!=times and len(ds[key])!=0:
          warnings.warn("error, data uneven. key:"+key+"num:"+str(len(ds[key])))
       print key
       s=0
       for v in ds[key]:
          s+=v
          print v
       avg=0
       if len(ds[key])!=0:
          avg=s/len(ds[key])
       print "avg:",avg
       statistics.append(key+",avg:"+str(avg))
  print "=================="
  for r in statistics:
       print r
  print "total:",cnt

