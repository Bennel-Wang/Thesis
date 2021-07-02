import collections
import csv
from graphviz import Digraph
import para

def treeVisualization():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/tc_inside' + str(para.fileNumber) + '_alert.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                nodeList = []
                edgeFreq = collections.defaultdict(int)
                edgeList = []
                recordNum = 0
                dot = Digraph(name='connection-record' + str(para.fileNumber) + 'original connection',
                              comment='connection-record' + str(para.fileNumber) + 'original connection', format="png")

                continue
            else:
                l = {'Time': l[0],'SrcPort':l[1],'SrcIp':l[2],'DesPort':l[3],'DesIp':l[4],'AlertType':l[5]}
                edgeFreq[(l['SrcIp'],l['DesIp'])] = edgeFreq[(l['SrcIp'],l['DesIp'])] + 1
                if (l['SrcIp'] + '-' + l['DesIp']) not in edgeList:
                    edgeList.append(l['SrcIp'] + '-' + l['DesIp'])

        for edge in edgeList:
            srcIp, desIp = edge.split('-')
            if edgeFreq[(srcIp,desIp)]  >= j*para.IpNumT:
                dot.edge(srcIp,  desIp, label=str(edgeFreq[(srcIp,desIp)]))
                if srcIp not in nodeList:
                    dot.node(name=srcIp, label=srcIp)
                    nodeList.append(srcIp)
                if desIp not in nodeList:
                    dot.node(name=desIp, label=desIp)
                    nodeList.append(desIp)



    dot.render(filename='Ip_Tree_file_' + str(para.fileNumber), directory="/home/jin/Documents/Iptree",view =True)