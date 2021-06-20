import collections
import csv
from graphviz import Digraph
from datastructure import fileNumber

def resultVisualization():
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
                    linkFreq[cA + '-' + l['currAlert']] = linkFreq[cA + '-' + l['currAlert']] + 1
                    if cA != '[' and cA!=']' and cA != ', ':
                        cA = cA.split('-')[0]
                        if linkFreq[cA +'-'+ l['currAlert']]>=0 and ((cA +'-'+ l['currAlert']) not in edgeList) and cA != l['currAlert']:
                            print(cA, l['currAlert'])
                            dot.edge(cA, l['currAlert'])
                            edgeNum = edgeNum + 1
                            edgeList.append(cA +'-'+ l['currAlert'])
    print(edgeNum)
    dot.render(filename='connection-record' + str(fileNumber) + '-0618-color-hyper', directory="/home/jin/Documents/Generated Data",view =True)

def originVisualization():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/tc_inside' + str(fileNumber) + '_alert.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                nodeList = []
                lastAlert = ''
                edgeList = []
                edgeNum = 0
                dot = Digraph(name='connection-record' + str(fileNumber) + 'original connection',
                              comment='connection-record' + str(fileNumber) + 'original connection', format="png")

                continue
            else:
                l = {'Time': l[0],'SrcPort':l[1],'SrcIp':l[2],'DesPort':l[3],'DesIp':l[4],'AlertType':l[5]}
                if l['AlertType'] not in nodeList:
                    dot.node(name=l['AlertType'], label=l['AlertType'])
                    nodeList.append(l['AlertType'])
                if lastAlert and (lastAlert+'-'+ l['AlertType']) not in edgeList and lastAlert != l['AlertType']:
                    dot.edge(lastAlert, l['AlertType'])
                    edgeNum = edgeNum + 1
                    edgeList.append(lastAlert +'-'+ l['AlertType'])
                lastAlert = l['AlertType']

    print(edgeNum)
    dot.render(filename='original connection' + str(fileNumber), directory="/home/jin/Documents/Generated Data",view =True)


def labelVisualization():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/DDoS' + str(fileNumber) + '.csv', 'r') as f:
        reader = csv.reader(f)
        nodeList = []
        lastAlert = ''
        edgeList = []
        edgeNum = 0
        dot = Digraph(name='connection-record' + str(fileNumber) + 'original connection',
                      comment='connection-record' + str(fileNumber) + 'original connection', format="png")
        for (j, l) in enumerate(reader):
            l = {'Time': l[0],'SrcPort':l[1],'SrcIp':l[2],'DesPort':l[3],'DesIp':l[4],'AlertType':l[5]}
            if l['AlertType'] not in nodeList:
                dot.node(name=l['AlertType'], label=l['AlertType'])
                nodeList.append(l['AlertType'])
            if lastAlert and (lastAlert+'-'+ l['AlertType']) not in edgeList and lastAlert != l['AlertType']:
                dot.edge(lastAlert, l['AlertType'])
                edgeNum = edgeNum + 1
                edgeList.append(lastAlert +'-'+ l['AlertType'])
            lastAlert = l['AlertType']

    print(edgeNum)
    dot.render(filename='label connection' + str(fileNumber), directory="/home/jin/Documents/Generated Data",view =True)
