#!/usr/bin/env python3
import argparse
import networkx as nx
import re

#Regular expression to find callee
pattern = re.compile('@.*?\(')

def node_name (name):
  if is_cg:
    return "\"{%s}\"" % name
  else:
    return "\"{%s" % name

#################################
# Find the graph node for a name
#################################
def find_nodes (name):
  n_name = node_name (name)
  n_list = list (filter (lambda d: 'label' in d[1] and n_name in d[1]['label'], G.nodes(data=True)))
  if len (n_list) > 0:
    return n_list
  else:
    return []

##################################
# Calculate Distance
##################################
def distance (name):
  
  distance = -1
  for (n, _) in find_nodes (name):
    d = 0.0
    i = 0
    if is_cg:
      for (t, _) in targets:
        if nx.has_path (G, n, t):
          shortest = nx.dijkstra_path_length (G, n, t)
          d += 1.0 / (1.0 + shortest)
          i += 1
    else:
      for t_name in bb_distance:
        di = 0.0
        ii = 0
        for (t, _) in find_nodes(t_name):
          #Check if path exists
          if nx.has_path (G, n, t) :
            shortest = nx.dijkstra_path_length(G, n, t)
            di += 1.0 / (1.0 + 10 * bb_distance[t_name] + shortest)
            ii += 1
        if ii != 0:
          d += di / ii
          i += 1

    if d != 0 and (distance == -1 or distance > i / d) :
      distance = i / d

  if distance != -1:
    out.write (name)
    out.write (",")
    out.write (str (distance))
    out.write ("\n")

# Main function
if __name__ == '__main__':
  parser = argparse.ArgumentParser ()
  parser.add_argument ('-d', '--dot', type=str, required=True, help="Path to dot-file representing the graph.")
  parser.add_argument ('-t', '--targets', type=str, required=True, help="Path to file specifying Target nodes.")
  parser.add_argument ('-o', '--out', type=str, required=True, help="Path to output file containing distance for each node.")
  parser.add_argument ('-n', '--names', type=str, required=True, help="Path to file containing name for each node.")
  parser.add_argument ('-c', '--cg_distance', type=str, help="Path to file containing call graph distance.")
  parser.add_argument ('-s', '--cg_callsites', type=str, help="Path to file containing mapping between basic blocks and called functions.")

  args = parser.parse_args ()

  print ("\nParsing %s .." % args.dot)
  G = nx.DiGraph(nx.drawing.nx_pydot.read_dot(args.dot))
  print (nx.info(G))

  is_cg = 1 if "Name: Call graph" in nx.info(G) else 0
  print ("\nWorking in %s mode.." % ("CG" if is_cg else "CFG"))

  # Process as ControlFlowGraph
  caller = ""
  cg_distance = {}
  bb_distance = {}
  if not is_cg :

    if args.cg_distance is None:
      print ("Specify file containing CG-level distance (-c).")
      exit(1)

    elif args.cg_callsites is None:
      print ("Specify file containing mapping between basic blocks and called functions (-s).")
      exit(1)

    else:

      caller = args.dot.split(".")
      caller = caller[len(caller)-2]
      print ("Loading cg_distance for function '%s'.." % caller)

      with open(args.cg_distance, 'r') as f:
        for l in f.readlines():
          s = l.strip().split(",")
          cg_distance[s[0]] = float(s[1])

      with open(args.cg_callsites, 'r') as f:
        for l in f.readlines():
          s = l.strip().split(",")
          if len(find_nodes(s[0])) > 0:
            if s[1] in cg_distance:
              if s[0] in bb_distance:
                if bb_distance[s[0]] > cg_distance[s[1]]:
                  bb_distance[s[0]] = cg_distance[s[1]]
              else:
                bb_distance[s[0]] = cg_distance[s[1]]

      print ("Adding target BBs (if any)..")
      with open(args.targets, "r") as f:
        for l in f.readlines ():
          s = l.strip().split("/");
          line = s[len(s) - 1]
          nodes = find_nodes(line)
          if len(nodes) > 0:
            bb_distance[line] = 0
            print ("Added target BB!")

  # Process as CallGraph
  else:

    print ("Loading targets..")
    with open(args.targets, "r") as f:
      targets = []
      for line in f.readlines ():
        line = line.strip ()
        for target in find_nodes(line):
          targets.append (target)

    if (len (targets) == 0 and is_cg):
      print ("No targets available")
      exit(1)

  print ("Calculating distance..")
  with open(args.out, "w") as out:
    with open(args.names, "r") as f:
      for line in f.readlines():
        line = line.strip()
        distance (line)
