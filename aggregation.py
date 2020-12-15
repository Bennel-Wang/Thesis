import csv
import re
import collections
import pandas as pd
from graphviz import Digraph

def visualization(dataList, filename):
    dot = Digraph(name=filename, comment="attack graph generation", format="png")
    for node in dataList:
        node[0] = re.sub(r':', ";", node[0]) #process IPV6 address to prevent : as delimiter
        node[1] = re.sub(r':', ";", node[1]) #process IPV6 address to prevent : as delimiter
        dot.node(name=node[0], label='SrcIp:' + node[0] , color='green')    #name = DesIp, label = Protocol

    for node in dataList:  #when no destination, there may be error
        la = 'FirstTime: ' + node[5] + 's\n' +' LastTime: '+ node[6] + 's' + '\n' + node[2]
        if (node[2] == 'TCP'):
            la = la + '\nSrcPort:' + node[3] + '\nDesPort:' + node[4]
        dot.edge(node[0], node[1], label = la, color='red')
    dot.render(filename=filename, directory='/home/jin/Documents/Generated Img',view=False)

def aggregation(groupResult, newLine):
    slideTWin = 10000    #interval for aggregating the same information tuple (ip, port, protocol)as last appear time and current appear time---can be leave out because of duplication
    for (i,result) in enumerate(groupResult):
        # do not do anything if Ip, port, Protocol are the same and the time is in the sliding window--tuple content
        if((result[0] == newLine[0]) and (result[1] == newLine[1]) and
                (result[2] == newLine[2]) and (result[3] == newLine[3]) and (result[4] == newLine[4])):       #information are the same--appear before
            if (validTimeGap(result[6], newLine[6], slideTWin)):    #in sliding window
                groupResult[i][6] = newLine[6]
                return
            else:   #not in sliding window
                if(newLine[5] == '-'):
                    newLine[5] = newLine[6]
                groupResult.append(newLine)
                return
    else:       #tuple content are unique
        newLine[5] = newLine[6]
        groupResult.append(newLine)
        return

#whether the gap of two inputs is bigger the the preset value
def validTimeGap(timeFormer, timeLatter, validGap):
    if float(timeLatter) - float(timeFormer) > validGap:
        return False
    else:
        return True

def dataprocessing():
    #initialization
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside (test).csv', 'r') as f:
        reader = csv.reader(f)
        result = [['SrcIp', 'DesIP','Protocol', 'SrcPort', 'DesPort', 'First time', 'Last time']]
        group = 0
        validInterval = 10000          #interval between Ip last and current appearance
        IpGroup = collections.defaultdict(int)
        IpLastTime = collections.defaultdict(str)
        SrcIpFreq = collections.defaultdict(int)
        DesIpFreq = collections.defaultdict(int)
        #relatedIpDict = collections.defaultdict(int)
        for (i,l) in enumerate(reader):

            # remove the head
            if(i == 0):
                continue
            else:

                # get the data, re-organize them
                pattern = re.compile(r'(.*)  >  (.*)')
                matchObj = pattern.match(l[6])
                if (matchObj):
                    l = {'No.id': l[0], 'Time': l[1], 'SrcIp': l[2], 'DesIp': l[3], 'Protocol': l[4], 'SrcPort':matchObj.group(1),'DesPort':matchObj.group(2).split(' ')[0],'Len': l[5],
                         'Info': l[6]}
                else:
                    l = {'No.id': l[0], 'Time': l[1], 'SrcIp': l[2], 'DesIp': l[3], 'Protocol': l[4], 'SrcPort':'-','DesPort':'-', 'Len': l[5],
                         'Info': l[6]}


                #add the source Ips to the frequency dictionary, build relationship between the previous dest and the current src
                if (SrcIpFreq[l['SrcIp']] == 0):                    #SrcIp not as SrcIp before
                    SrcIpFreq[l['SrcIp']] = 1                       #initialize the frequency of SrcIP
                    if (DesIpFreq[l['SrcIp']] == 0):                #and SrcIp not as DesIp before
                        IpLastTime[l['SrcIp']] = l['Time']
                        IpLastTime[l['DesIp']] = l['Time']
                        group = group + 1                           #new a group and add the SrcIP and DesIp to the group
                        IpGroup[l['SrcIp']] = group
                        IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                        print('Initialize SrcIp ', l['SrcIp'], ' > ', l['DesIp'], ' time = ', l['Time'],  l['Info'], 'Attack tree group = ', IpGroup[l['SrcIp']])
                        result.append([])
                        aggregation(result[IpGroup[l['SrcIp']]],
                                    [l['SrcIp'], l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort'], l['Time'], l['Time']])  #IP initialize: first appear time = last appear time
                        #result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort']])
                    else:                                           #but Src as Des before
                        #relatedIpDict[l['SrcIp']] = relatedIpDict[l['SrcIp']] + 1
                        if (validTimeGap(IpLastTime[l['SrcIp']], l['Time'], validInterval)):    #if the time interval between Ip current and last appearance, link the path
                            IpLastTime[l['SrcIp']] = l['Time']
                            IpLastTime[l['DesIp']] = l['Time']
                            IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                            print(l['SrcIp'], ' > ', l['DesIp'],  ' time = ', l['Time'], l['Info'], ' group = ', IpGroup[l['SrcIp']])
                            aggregation(result[IpGroup[l['SrcIp']]],
                                        [l['SrcIp'], l['DesIp'], l['Protocol'], l['SrcPort'], l['DesPort'], l['Time'], l['Time']]) #IP initialize: first appear time = last appear time
                            #result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort']])
                        else:                                                       #otherwise, break and create a new path
                            IpLastTime[l['SrcIp']] = l['Time']
                            IpLastTime[l['DesIp']] = l['Time']
                            group = group + 1  # new a group and add the SrcIP and DesIp to the group
                            IpGroup[l['SrcIp']] = group
                            IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                            print('Initialize SrcIp ', l['SrcIp'], ' > ', l['DesIp'], ' time = ', l['Info'],
                                  'Attack tree group = ', IpGroup[l['SrcIp']])
                            # result.append([['Ip', 'Time', 'Type']])
                            result.append([])
                            aggregation(result[IpGroup[l['SrcIp']]],
                                        [l['SrcIp'], l['DesIp'], l['Protocol'], l['SrcPort'], l['DesPort'], l['Time'], l['Time']]) #IP initialize: first appear time = last appear time
                            #result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort']])
                else:                                               #SrcIp as Src before
                    if (validTimeGap(IpLastTime[l['SrcIp']], l['Time'], validInterval)):   #if the time interval between Ip current and last appearance, link the path
                        IpLastTime[l['SrcIp']] = l['Time']
                        IpLastTime[l['DesIp']] = l['Time']
                        SrcIpFreq[l['SrcIp']] = SrcIpFreq[l['SrcIp']] + 1
                        IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                        print(l['SrcIp'], ' > ', l['DesIp'], ' time = ', l['Time'], l['Info'], ' group = ', IpGroup[l['SrcIp']])
                        aggregation(result[IpGroup[l['SrcIp']]],
                                    [l['SrcIp'], l['DesIp'], l['Protocol'], l['SrcPort'], l['DesPort'], '-',l['Time']])
                        #result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort']])
                    else:                                                       # otherwise, break and create a new path
                        IpLastTime[l['SrcIp']] = l['Time']
                        IpLastTime[l['DesIp']] = l['Time']
                        SrcIpFreq[l['SrcIp']] = SrcIpFreq[l['SrcIp']] + 1
                        group = group + 1  # new a group and add the SrcIP and DesIp to the group
                        IpGroup[l['SrcIp']] = group
                        IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                        print('Initialize SrcIp ', l['SrcIp'], ' > ', l['DesIp'], ' time = ',l['Time'], l['Info'],
                              'Attack tree group = ', IpGroup[l['SrcIp']])
                        # result.append([['Ip', 'Time', 'Type']])
                        result.append([])
                        aggregation(result[IpGroup[l['SrcIp']]],
                                    [l['SrcIp'], l['DesIp'], l['Protocol'], l['SrcPort'], l['DesPort'], l['Time'], l['Time']])
                        #result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort']])

                #add the destioation Ips to the frequency dictionary,  the previous des and the current des
                if (DesIpFreq[l['DesIp']] == 0):
                    DesIpFreq[l['DesIp']] = 1
                else:
                    DesIpFreq[l['DesIp']] = DesIpFreq[l['DesIp']] + 1
                    #relatedIpDict[l['DesIp']] = relatedIpDict[l['DesIp']] + 1

        #for relatedIp in relatedIpDict:
        #    print('relatedIp = ', relatedIp, 'relatedFreq = ', relatedIpDict[relatedIp])

        groupNum = len(result) - 1
        name = ['SrcIp', 'DesIp', 'Protocol', 'SrcPort', 'DesPort','FirstAppearTime','LastAppearTime']
        for i in range (1, groupNum+1):
            IpPairNum = len(result[i])
            if IpPairNum > 1:
                data = pd.DataFrame(columns = name, data = result[i])
                data.to_csv('/home/jin/Documents/Generated Data/data_group'+ str(i))
                visualization(result[i],'graph_group'+ str(i))
        #print(result)
        print('output done')


if __name__ == '__main__':
    dataprocessing()