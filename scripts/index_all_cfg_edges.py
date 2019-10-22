#!/usr/bin/env python

import argparse
import networkx as nx
import os        
def read_into_buffer(filename):
    buf = bytearray(os.path.getsize(filename))
    with open(filename, 'rb') as f:
        f.readinto(buf)
    f.close()
    return buf
def get_margin_node_rids(networkID2rid,GG):
    ret=[]
    for u,v in GG.in_edges:
        if GG.nodes[u]['cov']==1 and GG.edges[u,v]['cov']==0:
            if u in networkID2rid:
                ret.apend(networkID2rid[u])
    for n in GG.nodes:
        if GG.nodes[n]['cov']==1 and len(GG.in_edges)==0 and len(GG.out_edges)==0:
            if n in networkID2rid:
                ret.apend(networkID2rid[n])
    return ret
def merge_all_cfg(file_dir):
    GG = nx.DiGraph()
    print "Init empty Graph",nx.info(GG)
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            array=file.split(".")
            if array[0]=="cfg" and array[-1]=="dot" :
                if array[-2]=="bigger" and array[-3]=="dot":
                    continue
                print "\nParsing %s .." % file 
                G = nx.DiGraph(nx.drawing.nx_pydot.read_dot (file_dir+"/"+file))
                print nx.info (G)
                GG=nx.compose(GG,G)#GG=nx.union(GG,G,rename=('GG-','G-'))
    print nx.info(GG)
    return GG
def getNameFromLabel(n,GG):
    node=GG.nodes[n]
    #print node,n
    #e.g. 
    #{'shape': 'record', 'cov': 0, 'label': '"{entry.c:34:}"'}
    #{'shape': 'record', 'cov': 0, 'label': '"{entry.c:26:|{<s0>T|<s1>F}}"'}
    #{'shape': 'record', 'cov': 0, 'label': '"{%23}"'}
    if node.has_key("label") and ":" in node["label"]:
       array=node["label"].split(":")
       return array[0][2:]+":"+array[1]
    return str(n)
# Main function
if __name__ == '__main__':
  is_cg = 1
  was_added = 0
  parser = argparse.ArgumentParser ()    
  parser.add_argument ('-d', '--dot_path', type=str, required=True, help="The dot-file directory in which each dot file represents a CFG of a function")
  args = parser.parse_args ()
  print "\nParsing %s .." % args.dot_path 
  GG=merge_all_cfg(args.dot_path)
  nx.drawing.nx_pydot.write_dot(GG, args.dot_path+"/merge_all_cfg.dot")
  
  networkID2bbname=dict()
  bbname2networkID=dict()
  #init
  for u,v in GG.edges:
      GG.edges[u,v]['cov']=0
  for n in GG.nodes:
      GG.nodes[n]['cov']=0
      bbname2networkID[getNameFromLabel(n,GG)]=n
      networkID2bbname[n]=getNameFromLabel(n,GG)
      #print GG.nodes.data()
  f=open(args.dot_path+'/../bbname_rid_pairs.txt', "r")
  
  bbname2rid=dict()
  rid2bbname=dict()
  lines=f.readlines()
  f.close()
  indexes=[]
  for line in lines:
      bb_name,rid=line.split(",")
      rid=rid.strip()
      bbname2rid[bb_name]=rid
      rid2bbname[rid]=bb_name
      indexes.append([bb_name,rid])
  networkID2rid=dict()
  rid2networkID=dict()
  node_index=[]
  for id,bbname in networkID2bbname.items():
     if bbname in bbname2rid:
         networkID2rid[id]= bbname2rid[bbname]   
         rid2networkID[bbname2rid[bbname]]=id 
         node_index.append(bbname2rid[bbname]+","+bbname+","+str(id)+"\n")
  
  node_index=list(set(node_index))
  node_index.sort()
  node_index_file=open(args.dot_path+'/../node_index.txt','w+')
  node_index_file.writelines(node_index)
  node_index_file.close()
  
  out_edge_index=[]
  in_edge_index=[]
  
  for u,v in GG.edges:
      if u in networkID2rid and v in networkID2rid:
          out_edge_index.append((int(networkID2rid[u]),int(networkID2rid[v])))
          in_edge_index.append((int(networkID2rid[v]),int(networkID2rid[u])))
  out_edge_index=list(set(out_edge_index))
  out_edge_index.sort()  
  in_edge_index=list(set(in_edge_index))
  in_edge_index.sort()      
  out_edge_index_file=open(args.dot_path+'/../out_edge_index.txt','w+')
  in_edge_index_file=open(args.dot_path+'/../in_edge_index.txt','w+')
  
  for i in range(len(out_edge_index)):
      out_edge_index_file.write(str(out_edge_index[i][0])+","+str(out_edge_index[i][1])+"\n")
      in_edge_index_file.write(str(in_edge_index[i][0])+","+str(in_edge_index[i][1])+"\n")

  out_edge_index_file.close()
  in_edge_index_file.close()
  #if necessary dump these dict index to files to augment C program running.
  
# #read from #/home/yangke/Program/AFL/aflgo/aflgo/tutorial/samples/work/out/entry_result/fuzz_bitmap
# buf=read_into_buffer(args.dot_path+'/../../out/entry_result/fuzz_bitmap')
# #update(buf,GG,networkID2rid)
# for u,v in GG.edges:
#   if GG.edges[u,v]['cov']==0:
#       if u in networkID2rid and v in networkID2rid:
#           pos=(int(networkID2rid[u])>>1) ^(int(networkID2rid[v]))
#           info= "buf[%d]=%d" % (pos,buf[pos])
#           if buf[pos]!=255:
#               GG.edges[u,v]['cov']=1
#               print info,"covered!"
#           else:
#               print info,"uncover."
# rids=get_margin_node_rids(networkID2rid,GG);
# print rids
# #rid is our result
# #print list(GG.nodes.data())   
#    

 
