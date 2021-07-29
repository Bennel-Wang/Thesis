#ground truth, algorithm input and algorithm output Petri net visualization
import collections
import csv
from graphviz import Digraph
import para
import os

#Visualization for Petri net of algorithm output alerts
def resultVisualization():
    file_dir = '/home/jin/Documents/FinalResult/Scenario' + str(para.fileNumber) + '/'
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            with open(file_dir + file, 'r') as f:
                reader = csv.reader(f)
                for (j, l) in enumerate(reader):
                    # remove the head
                    if (j == 0):
                        nodeList = []
                        edgeList = []
                        edgeNum = 0
                        linkFreq = collections.defaultdict(int)
                        lastAlert = 'Start'
                        dot = Digraph(name='connection-record' + str(para.fileNumber) + '-01.07', comment='connection-record' + str(para.fileNumber), format="png")
                        continue
                    else:
                        l = {'Time': l[0], 'currAlert': l[1], 'prerequisite': [lastAlert], 'State': l[7]}
                        if l['State'] != 'Outside Step':
                            if l['currAlert'] not in nodeList:
                                dot.node(name=l['currAlert'], label=l['currAlert'])
                                nodeList.append(l['currAlert'])
                            for pA in l['prerequisite']:
                                if (pA +'-'+ l['currAlert']) not in edgeList:
                                    edgeList.append(pA +'-'+ l['currAlert'])
                                linkFreq[pA + '-' + l['currAlert']] = linkFreq[pA + '-' + l['currAlert']] + 1
                            lastAlert = l['currAlert']
                for e in edgeList:
                    dot.edge(e.split('-')[0], e.split('-')[1], label= str(linkFreq[e]))
            print(edgeNum)
            dot.render(filename='connection-record' + str(para.fileNumber) + '-01.07', directory="/home/jin/Documents/FinalResult",view =True)

#Visualization for Petri net of algorithm labelled alerts
def labelVisualization():
    file_dir = '/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/Ground True/'
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            with open(file_dir + file, 'r') as f:
                reader = csv.reader(f)
                for (j, l) in enumerate(reader):
                    # remove the head
                    if (j == 0):
                        nodeList = []
                        edgeList = []
                        edgeNum = 0
                        linkFreq = collections.defaultdict(int)
                        lastAlert = 'Start'
                        dot = Digraph(name='connection-record' + str(para.fileNumber) + '-01.07', comment='connection-record' + str(para.fileNumber), format="png")
                    l = {'Time': l[0], 'currAlert': l[5], 'prerequisite': [lastAlert]}
                    if l['currAlert'] not in nodeList:
                        dot.node(name=l['currAlert'], label=l['currAlert'])
                        nodeList.append(l['currAlert'])
                    for pA in l['prerequisite']:
                        if (pA +'-'+ l['currAlert']) not in edgeList:
                            edgeList.append(pA +'-'+ l['currAlert'])
                        linkFreq[pA + '-' + l['currAlert']] = linkFreq[pA + '-' + l['currAlert']] + 1
                    lastAlert = l['currAlert']
                for e in edgeList:
                    dot.edge(e.split('-')[0], e.split('-')[1], label= str(linkFreq[e]))
            print(edgeNum)
            dot.render(filename='connection-record' + file + '-01.07', directory="/home/jin/Documents/FinalResult",view =True)

#Visualization for Petri net of algorithm input alerts
def originalVisualization():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/tc_inside' + str(para.fileNumber) + '_alert.csv',
              'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                nodeList = []
                edgeList = []
                edgeNum = 0
                linkFreq = collections.defaultdict(int)
                lastAlert = 'Start'
                dot = Digraph(name='connection-record' + str(para.fileNumber) + '-01.07', comment='connection-record' + str(para.fileNumber), format="png")
                continue
            else:
                l = {'Time': l[0], 'currAlert': l[5], 'prerequisite': [lastAlert]}
                if l['currAlert'] not in nodeList:
                    dot.node(name=l['currAlert'], label=l['currAlert'])
                    nodeList.append(l['currAlert'])
                for pA in l['prerequisite']:
                    if (pA +'-'+ l['currAlert']) not in edgeList:
                        edgeList.append(pA +'-'+ l['currAlert'])
                    linkFreq[pA + '-' + l['currAlert']] = linkFreq[pA + '-' + l['currAlert']] + 1
                lastAlert = l['currAlert']
        for e in edgeList:
            dot.edge(e.split('-')[0], e.split('-')[1], label= str(linkFreq[e]))
    print(edgeNum)
    dot.render(filename='connection-record' + str(para.fileNumber) + '-01.07', directory="/home/jin/Documents/Original",view =True)

