import collections
import csv
from graphviz import Digraph
from datastructure import fileNumber

def visualization():
    with open('/home/jin/Documents/Generated Data/1806_record_hyper' + str(fileNumber) + '.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                nodeList = []
                edgeList = []
                edgeNum = 0
                linkFreq = collections.defaultdict(int)
                dot = Digraph(name='connection-record' + str(fileNumber) + '-0618-color-hyper', comment='connection-record' + str(fileNumber) + '-0618-color-hyper', format="png")
                continue
            else:
                l = {'Time': l[0], 'currAlert': l[1], 'prerequisite': l[4]}
                if l['currAlert'] not in nodeList:
                    dot.node(name=l['currAlert'], label=l['currAlert'])
                    nodeList.append(l['currAlert'])
                for cA in l['prerequisite'].split("'"):
                    linkFreq[cA + '-' + l['currAlert']] = linkFreq[cA + '-' + l['currAlert']] + 1 #filter because is weak link
                    if cA != '[' and cA!=']' and cA != ', ':
                        cA = cA.split('-')[0]
                        if linkFreq[cA +'-'+ l['currAlert']]>=0 and ((cA +'-'+ l['currAlert']) not in edgeList) and cA != l['currAlert']:
                            print(cA, l['currAlert'])
                            dot.edge(cA, l['currAlert'])
                            edgeNum = edgeNum + 1
                            edgeList.append(cA +'-'+ l['currAlert'])
    print(edgeNum)
    dot.render(filename='connection-record' + str(fileNumber) + '-0618-color-hyper', directory="/home/jin/Documents/Generated Data",view =True)

