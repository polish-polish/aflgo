#!/usr/bin/env python

import argparse
import os
import re
import subprocess
import warnings 
# Main function
if __name__ == '__main__':

  parser = argparse.ArgumentParser ()
  parser.add_argument ('-t', '--temp_dir', type=str, required=True, help="The temp dir")
  parser.add_argument ('-c', '--code_dir', type=str, required=True, help="The code dir")
  args = parser.parse_args ()
  print "\nTEMP_DIR: %s" % args.temp_dir
  print "\nCODE_DIR: %s" % args.code_dir

  info_path=args.temp_dir+"/bb_branch_info"

  for fname in os.listdir(info_path):
      f=open(info_path+'/'+fname,'r')
      lines=f.readlines()
      fixed_lines=[]
      for line in lines:
         m=re.search(".PLEASE_REPLACE_ME",line)
         if m:
            var=line[0:m.span()[0]].split('"')[1]
            cmd="grep '" +var+ "' " + args.code_dir + "" + " -rn --binary-files=without-match"
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            out, err = p.communicate()
            replaced=""
            for li in out.splitlines():
                if "#define" in li:
                    m2=re.search('".*"',li)
                    if m2:
                       replaced=m2.group()
                       break
                    elif re.search(r'\{.*\}',li):
                       m3=re.search(r'\{.*\}',li)
                       array=m3.group().lstrip('{').rstrip('}').split(',')
                       replaced=""
                       for a in array:
                           a=a.strip()
                           if re.match(r"'.*'",a):
                               if "\\" not in a:
                                   replaced+=a[1]
                           else:
                               replaced+=chr(int(a))
                       break
            new_line=line
            if replaced!="":
                print "Replace %s with %s" % (var,replaced)
                new_line=line.replace(var+".PLEASE_REPLACE_ME",replaced)
            fixed_lines.append(new_line);
         else:
            fixed_lines.append(line);
            
      f.close()
      f=open(info_path+'/'+fname,'w')
      f.writelines(fixed_lines)
      f.close()
  print "Done"
