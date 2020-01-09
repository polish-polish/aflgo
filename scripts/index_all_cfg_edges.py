#!/usr/bin/env python

import argparse
import networkx as nx
import os
import warnings    
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
def merge_all_cfg():
    f=open(args.temp_dir+'/distance.callgraph.txt', "r")
    lines=f.readlines();
    valid_fnames=set(map(lambda x: x.split(",")[0].strip(), lines))

    GG = nx.MultiDiGraph()
    print "Init empty Graph",nx.info(GG)
    for fname in valid_fnames:
        print "\nParsing %s .." % fname
        G = nx.MultiDiGraph(nx.drawing.nx_pydot.read_dot (args.temp_dir+"/dot-files/cfg."+fname+".dot"))
        print nx.info (G)
        GG=nx.compose(GG,G)#GG=nx.union(GG,G,rename=('GG-','G-'))
    '''
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            array=file.split(".")
            if array[0]=="cfg" and array[-1]=="dot" :
                if array[-2]=="bigger" and array[-3]=="dot":
                    continue
		if array[1] in valid_fnames:
                    print "\nParsing %s .." % file 
                    G = nx.DiGraph(nx.drawing.nx_pydot.read_dot (file_dir+"/"+file))
                    print nx.info (G)
                    GG=nx.compose(GG,G)#GG=nx.union(GG,G,rename=('GG-','G-'))
    '''
    print nx.info(GG)
    return GG
def getNameFromLabel(n,GG):
    node=GG.nodes[n]
    #print node,n
    #e.g. 
    #{'shape': 'record', 'cov': 0, 'label': '"{entry.c:34:5}"'}
    #{'shape': 'record', 'cov': 0, 'label': '"{entry.c:26:10|{<s0>T|<s1>F}}"'}
    #{'shape': 'record', 'cov': 0, 'label': '"{%23}"'}
    if node.has_key("label"):
       if "|" in node["label"]:
           array=node["label"].split("|")
           return array[0][2:]
       elif ":" in node["label"]:
           return node["label"][2:-2]
    #return str(n)
    return "@"
#dedulplicate
def dedulplicate(lines):
    ls=[]
    s=set()
    for line in lines:
        it_preds_succs=line.strip().split(";")
        if(len(it_preds_succs)!=5):continue
        inc_id,rid,bb_name,predstr,succs_str=it_preds_succs
        if rid+";"+bb_name+";"+predstr+";"+succs_str not in s:
            s.add(rid+";"+bb_name+";"+predstr+";"+succs_str)
            ls.append(line)
    return ls   
# Main function
if __name__ == '__main__':
  is_cg = 1
  was_added = 0
  parser = argparse.ArgumentParser ()    
  parser.add_argument ('-t', '--temp-dir', type=str, required=True, help="The directory which contains `dot-files` and `rid_bbname_pairs.txt`")
  args = parser.parse_args ()
  print "\nParsing %s .." % args.temp_dir
  GG=merge_all_cfg()
  nx.drawing.nx_pydot.write_dot(GG, args.temp_dir+"/merge_all_cfg.dot")
  
  #MAP:rid=>path_set={pred_pred->pred->it->succ}
  #origin_file=args.temp_dir+"/rid_bbname_pairs.txt"
  #temp_file=args.temp_dir+"/rid_bbname_pairs2.txt"
  #os.system("cat "+origin_file+"|sort|uniq >"+temp_file+" && mv "+temp_file+" "+origin_file)
  f=open(args.temp_dir+'/rid_bbname_pairs.txt', "r")
  lines=f.readlines()
  f.close()
  lines=dedulplicate(lines)
  f=open(args.temp_dir+'/rid_bbname_pairs.txt', "w+")
  f.writelines(lines)
  f.close()
  key2rid=dict()
  rid2key=dict()
  rid_key_keystr=[]
  for line in lines:
      it_preds_succs=line.strip().split(";")
      if(len(it_preds_succs)!=5):continue
      inc_id,rid,bb_name,predstr,succs_str=it_preds_succs
      if succs_str=="":
          succs=[]
      else:
          succs=succs_str.split(",")
      if predstr=="":
          preds=[]
      else:
          preds=predstr.split(",")
      path_set=[]
      path_set.append(bb_name)
      if preds!=[]:
          for pred in preds:
              pred_bbname=pred.split("{")[0]
              if "{" in pred:
                  pred_preds=pred.split("{")[1].rstrip("}").split("#")
                  for pred_pred in pred_preds:
                      pred_pred_bbname=pred_pred.split("(")[0]
                      if "(" in pred_pred:
                          pred_pred_preds=pred_pred.split("(")[1].rstrip(")").split("&")
                          for pred_pred_pred in pred_pred_preds:
                              pred_pred_pred_bbname=pred_pred_pred
                              if succs!=[]:
                                  for succ in succs:
                                      path_set.append(pred_pred_pred_bbname+"->"+pred_pred_bbname+"->"+pred_bbname+"->"+bb_name+"->"+succ)
                              else:
                                  path_set.append(pred_pred_pred_bbname+"->"+pred_pred_bbname+"->"+pred_bbname+"->"+bb_name)        
                      elif succs!=[]:
                          for succ in succs:
                              path_set.append(pred_pred_bbname+"->"+pred_bbname+"->"+bb_name+"->"+succ)
                      else:
                          path_set.append(pred_pred_bbname+"->"+pred_bbname+"->"+bb_name)
              elif succs!=[]:
                  for succ in succs:
                      path_set.append(pred_bbname+"->"+bb_name+"->"+succ)
              else:
                  path_set.append(pred_bbname+"->"+bb_name)
      if len(path_set)==0:
          for succ in succs:
              path_set.append(bb_name+","+succ)
      '''
      if bb_name=="jdmarker.c:611":
          print path_set     
          x=1/0'''
          
      if rid not in rid2key:
          rid2key[rid]=[path_set]
      else:
          rid2key[rid].append(path_set)
          #warnings.warn("dulplicate rid:"+rid);
      rid_key_keystr.append((rid,path_set,bb_name+";"+predstr+";"+succs_str))
          
  
  
  #MAP:networkID=>path_set={pred_pred->pred->it->succ}  compare and generate map
  networkID2rid=dict()
  rid2networkID=dict()
  node_index_str=""
  for n in GG.nodes:
      bbname=getNameFromLabel(n,GG)
      path_set=[]
      path_set.append(getNameFromLabel(n,GG))
      for pred in GG.predecessors(n):
          t_set=[]
          for pred_pred in GG.predecessors(pred):
              q_set=[]
              for pred_pred_pred in GG.predecessors(pred_pred):
                  r_set=[]
                  for succ in GG.successors(n):
                      for whatever in range(GG.number_of_edges(n,succ)):
                         r_set.append(getNameFromLabel(pred_pred_pred,GG)+"->"+getNameFromLabel(pred_pred,GG)+"->"+getNameFromLabel(pred,GG)+"->"+getNameFromLabel(n,GG)+"->"+getNameFromLabel(succ,GG))
                  if len(r_set)==0:
                      r_set.append(getNameFromLabel(pred_pred_pred,GG)+"->"+getNameFromLabel(pred_pred,GG)+"->"+getNameFromLabel(pred,GG)+"->"+getNameFromLabel(n,GG))
                  for nothing in range(GG.number_of_edges(pred_pred_pred,pred_pred)):
                      q_set+=r_set
              if len(q_set)==0:
                  for succ in GG.successors(n):
                      for whatever in range(GG.number_of_edges(n,succ)):
                          q_set.append(getNameFromLabel(pred_pred,GG)+"->"+getNameFromLabel(pred,GG)+"->"+getNameFromLabel(n,GG)+"->"+getNameFromLabel(succ,GG))
                  if len(q_set)==0:
                      q_set.append(getNameFromLabel(pred_pred,GG)+"->"+getNameFromLabel(pred,GG)+"->"+getNameFromLabel(n,GG))
              for nothing in range(GG.number_of_edges(pred_pred,pred)):
                  t_set+=q_set
          if len(t_set)==0:
              for succ in GG.successors(n):
                  for whatever in range(GG.number_of_edges(n,succ)):
                      t_set.append(getNameFromLabel(pred,GG)+"->"+getNameFromLabel(n,GG)+"->"+getNameFromLabel(succ,GG))
              if len(t_set)==0:
                  t_set.append(getNameFromLabel(pred,GG)+"->"+getNameFromLabel(n,GG))
          for nothing in range(GG.number_of_edges(pred,n)):
              path_set+=t_set
      if len(path_set)==0:
          for succ in GG.successors(n):
              for whatever in range(GG.number_of_edges(n,succ)):
                  path_set.append(getNameFromLabel(n,GG)+"->"+getNameFromLabel(succ,GG))
          
      findit=False
      for rid,key,keystr in rid_key_keystr:
          a=dict()
          b=dict()
          for p in key:
              if p not in a:
                  a[p]=1
              else:
                  a[p]+=1
          for p in path_set:
              if p not in b:
                  b[p]=1
              else:
                  b[p]+=1
          if a==b:
              findit=True
              node_index_str+=rid+"|"+n+"|"+keystr+"\n"
              if n not in networkID2rid:
                  networkID2rid[n]=[rid]
              else:
                  print path_set
                  warnings.warn("dulplicate networkID:"+n+"\n insert "+rid+" to "+str(networkID2rid[n]));
                  networkID2rid[n].append(rid)
              if rid not in rid2networkID:
                  rid2networkID[rid]=[n]
              else:
                  #warnings.warn("dulplicate rid:"+rid+"\n insert "+n+" to "+str(rid2networkID[rid]));
                  rid2networkID[rid].append(n)
      if not findit:
          if "%" not in getNameFromLabel(n,GG):
              print path_set
              warnings.warn("ERROR cannot find rid for n="+n);
      #print GG.nodes.data()
  node_index_file=open(args.temp_dir+'/node_index.txt','w+')
  node_index_file.write(node_index_str)
  node_index_file.close()
  
  out_edges_dot_str=""
  out_edges_str=""
  in_edges_str=""
  dul_in=set()
  dul_out=set()
  for u,v,w in GG.edges:
      if u in networkID2rid and  v in networkID2rid:
          if len(set(networkID2rid[u])) > 1:
              if set(networkID2rid[u]).issubset(dul_out):continue
              dul_out|=set(networkID2rid[u])
          if len(set(networkID2rid[v])) > 1:
              if set(networkID2rid[v]).issubset(dul_in):continue
              dul_in|=set(networkID2rid[v])
          for rid_u in  networkID2rid[u]:
              for rid_v in  networkID2rid[v]:
                  out_edges_str+=rid_u+","+rid_v+"\n"
                  in_edges_str+=rid_v+","+rid_u+"\n"
                  out_edges_dot_str+=rid_u+"->"+rid_v+";\n"
      else:
          if "%" not in getNameFromLabel(n,GG):
              print "ERROR in mapping GG to rid graph, keystr missing"
              print "u:"+u+"\nv:"+v+"\n"
              x=1/0
  out_edge_index_file=open(args.temp_dir+'/out_edge_index.txt','w+')
  in_edge_index_file=open(args.temp_dir+'/in_edge_index.txt','w+')
  out_edge_index_dot_file=open(args.temp_dir+'/out_edge_index.dot','w+')
  out_edge_index_file.write(out_edges_str)
  in_edge_index_file.write(in_edges_str)
  out_edge_index_dot_file.write('digraph "merged CFG" {\nlabel="merged CFG";\n\n'+out_edges_dot_str+'}')
  out_edge_index_file.close()
  in_edge_index_file.close()
  out_edge_index_dot_file.close()
  cmd="dot -Tsvg "+args.temp_dir+"/out_edge_index.dot -o " +args.temp_dir+"/out_edge_index.svg"
  os.system(cmd)
  
 


  #if necessary dump these dict index to files to augment C program running.
  
# #read from #/home/yangke/Program/AFL/aflgo/aflgo/tutorial/samples/work/out/entry_result/fuzz_bitmap
# buf=read_into_buffer(args.temp_dir+'/../out/entry_result/fuzz_bitmap')
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

 
