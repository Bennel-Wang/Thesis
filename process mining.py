import collections
import csv
import re
import pandas as pd
from graphviz import Digraph
#add how many step finally have
#time threshold to separate steps can be calculated from relative value inside step

#linking relation
TLdict = {'DNS':{'Pre':['Start','P1'],'Pos':['P1']}, 'Portmap':{'Pre':['P1','P2','P3','P4'],'Pos':['P2']},'SADMIND':{'Pre':['P2'],'Pos':['P3']},
         'TCP':{'Pre':['P3','P4','P5','P6','P7','P8','P9','End'],'Pos':['P4']},'FTP':{'Pre':['P4','P5'],'Pos':['P5']}, 'FTP-Data':{'Pre':['P4','P6'], 'Pos':['P6']},
         'TELNET':{'Pre':['P4','P7'],'Pos':['P7']},'UDP':{'Pre':['P4','P7'],'Pos':['P8']}, 'ARP':{'Pre':['P4','P9'],'Pos':['P9']}, 'ICMP':{'Pre':['P8'],'Pos':['End']}}

#visiting relation
TVdict = {'DNS': False, 'Portmap': False,'SADMIND': False, 'TCP': False,'FTP': False, 'FTP-Data': False,'TELNET': False,'UDP': False, 'ARP': False, 'ICMP': False}

#initial Token number
Pdict ={'Start':0, 'P1':0, 'P2':0, 'P1':0, 'P2':0, 'P3':0, 'P4':0, 'P5':0, 'P6':0, 'P7':0, 'P8':0, 'P9':0, 'End':0}

def calfitness(sixToken,vdict):
    x = 0.001  #for denominator---minus result may because if it
    p = sixToken[0]
    c = sixToken[1]
    m = sixToken[2]
    r = sixToken[3]
    n = sixToken[4]
    a = sixToken[5]
    fitness = 1/3 * (1 - ((m+x)/(c+x))) + 1/3 * (1 - ((r+x)/(p+x))) + 1/3 * (1 - ((n+x)/(a+x)))    #for numerator and denominator all 0, fitness = 0
    s = 0
    for j in vdict.values():
        if j:
            s = s + 1
    #fitness = fitness*(s / len(vdict))
    return fitness

def processflow(groupNum, Protocol, sixTlist, TVdictlist, Pdictlist,Time):
    sixTlist[groupNum][5] = sixTlist[groupNum][5] + 1  #total token number
    if Protocol not in TLdict:
        sixTlist[groupNum][4] = sixTlist[groupNum][4] + 1
        return calfitness(sixTlist[groupNum],TVdictlist[groupNum])
    else:
        if(TVdictlist[groupNum][Protocol] == False):
            TVdictlist[groupNum][Protocol] = 'First:'+ Time   #mark as visited
        for preP in TLdict[Protocol]['Pre']:
            #if preP == 'Start':
            #    Pdictlist[groupNum][preP] = Pdictlist[groupNum][preP] + 1
            #    sixTlist[groupNum][0] = sixTlist[groupNum][0] + 1
            if (Pdictlist[groupNum][preP] > 0):
                Pdictlist[groupNum][preP] = Pdictlist[groupNum][preP] - 1
                sixTlist[groupNum][1] = sixTlist[groupNum][1] + 1   #consume 1 token
                break
        else:       #for else, if not consume, means missing
            sixTlist[groupNum][2] = sixTlist[groupNum][2] + 1   #missing token
            sixTlist[groupNum][1] = sixTlist[groupNum][1] + 1  # consume 1 token

        for posP in TLdict[Protocol]['Pos']:
            Pdictlist[groupNum][posP] = Pdictlist[groupNum][posP] + 1
            sixTlist[groupNum][0] = sixTlist[groupNum][0] + 1   #produce 1 token
        sixTlist[groupNum][3] = 0
        for p in Pdict:
            sixTlist[groupNum][3] = sixTlist[groupNum][3] + Pdictlist[groupNum][p]
        return calfitness(sixTlist[groupNum],TVdictlist[groupNum])


#aggregate the same type--ip+protocol+port if in the time interval
'''def aggregation(groupResult, newLine):
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
        return'''

#whether the gap of two inputs is bigger the the preset value
def validTimeGap(timeFormer, timeLatter, validGap):
    if float(timeLatter) - float(timeFormer) > validGap:
        return False
    else:
        return True

def dataprocessing():
    #initialization
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside.csv', 'r') as f: #test for 3000 cases
        reader = csv.reader(f)
        result = [['SrcIp', 'DesIP','Protocol', 'SrcPort', 'DesPort', 'First time', 'Last time']]       #the result of output file
        group = 0                       #one group output one file
        validInterval = 10000           #interval between Ip last and current appearance
        IpGroup = collections.defaultdict(int)
        IpLastTime = collections.defaultdict(str)
        SrcIpFreq = collections.defaultdict(int)
        DesIpFreq = collections.defaultdict(int)
        Flist = ['fitness']
        sixTlist = [['p','c','m','r','n','a']]
        visitTgroup = [TVdict]
        tokenNumgroup = [Pdict]
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
                        sixTlist.append([1,0,0,0,0,0])
                        visitTgroup.append(
                            {'DNS': False, 'Portmap': False, 'SADMIND': False, 'TCP': False, 'FTP': False,
                             'FTP-Data': False, 'TELNET': False, 'UDP': False, 'ARP': False, 'ICMP': False})
                        tokenNumgroup.append(
                            {'Start': 0, 'P1': 0, 'P2': 0, 'P1': 0, 'P2': 0, 'P3': 0, 'P4': 0, 'P5': 0, 'P6': 0,
                             'P7': 0, 'P8': 0, 'P9': 0, 'End': 0})
                        Flist.append(0)
                    else:                                           #but Src as Des before
                        #relatedIpDict[l['SrcIp']] = relatedIpDict[l['SrcIp']] + 1
                        if (validTimeGap(IpLastTime[l['SrcIp']], l['Time'], validInterval)):    #if the time interval between Ip current and last appearance, link the path
                            IpLastTime[l['SrcIp']] = l['Time']
                            IpLastTime[l['DesIp']] = l['Time']
                            IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                            print(l['SrcIp'], ' > ', l['DesIp'],  ' time = ', l['Time'], l['Info'], ' group = ', IpGroup[l['SrcIp']])
                            #aggregation(result[IpGroup[l['SrcIp']]],
                            #            [l['SrcIp'], l['DesIp'], l['Protocol'], l['SrcPort'], l['DesPort'], l['Time'], l['Time']]) #IP initialize: first appear time = last appear time
                            result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort']])
                            fitness = processflow(IpGroup[l['SrcIp']], l['Protocol'], sixTlist, visitTgroup, tokenNumgroup,l['Time'])
                            Flist[IpGroup[l['SrcIp']]]= fitness
                        else:                                                       #otherwise, break and create a new path
                            IpLastTime[l['SrcIp']] = l['Time']
                            IpLastTime[l['DesIp']] = l['Time']
                            group = group + 1  # new a group and add the SrcIP and DesIp to the group
                            IpGroup[l['SrcIp']] = group
                            IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                            print('Initialize SrcIp ', l['SrcIp'], ' > ', l['DesIp'], ' time = ', l['Info'],
                                  'Attack tree group = ', IpGroup[l['SrcIp']])
                            #result.append([['Ip', 'Time', 'Type']])
                            result.append([])
                            sixTlist.append([0, 0, 0, 0, 0, 0])
                            visitTgroup.append({'DNS': False, 'Portmap': False,'SADMIND': False, 'TCP': False,'FTP': False, 'FTP-Data': False,'TELNET': False,'UDP': False, 'ARP': False, 'ICMP': False})
                            tokenNumgroup.append({'Start':0, 'P1':0, 'P2':0, 'P1':0, 'P2':0, 'P3':0, 'P4':0, 'P5':0, 'P6':0, 'P7':0, 'P8':0, 'P9':0, 'End':0})
                            Flist.append(0)
                            #aggregation(result[IpGroup[l['SrcIp']]],
                            #            [l['SrcIp'], l['DesIp'], l['Protocol'], l['SrcPort'], l['DesPort'], l['Time'], l['Time']]) #IP initialize: first appear time = last appear time
                            result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort']])
                else:                                               #SrcIp as Src before
                    if (validTimeGap(IpLastTime[l['SrcIp']], l['Time'], validInterval)):   #if the time interval between Ip current and last appearance, link the path
                        IpLastTime[l['SrcIp']] = l['Time']
                        IpLastTime[l['DesIp']] = l['Time']
                        SrcIpFreq[l['SrcIp']] = SrcIpFreq[l['SrcIp']] + 1
                        IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                        print(l['SrcIp'], ' > ', l['DesIp'], ' time = ', l['Time'], l['Info'], ' group = ', IpGroup[l['SrcIp']])
                        fitness = processflow(IpGroup[l['SrcIp']], l['Protocol'], sixTlist, visitTgroup, tokenNumgroup,l['Time'])
                        Flist[IpGroup[l['SrcIp']]]= fitness
                        #aggregation(result[IpGroup[l['SrcIp']]],
                        #            [l['SrcIp'], l['DesIp'], l['Protocol'], l['SrcPort'], l['DesPort'], '-',l['Time']])
                        result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort']])
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
                        sixTlist.append([0, 0, 0, 0, 0, 0])
                        visitTgroup.append(
                            {'DNS': False, 'Portmap': False, 'SADMIND': False, 'TCP': False, 'FTP': False,
                             'FTP-Data': False, 'TELNET': False, 'UDP': False, 'ARP': False, 'ICMP': False})
                        tokenNumgroup.append(
                            {'Start': 0, 'P1': 0, 'P2': 0, 'P1': 0, 'P2': 0, 'P3': 0, 'P4': 0, 'P5': 0, 'P6': 0,
                             'P7': 0, 'P8': 0, 'P9': 0, 'End': 0})
                        Flist.append(0)
                        #aggregation(result[IpGroup[l['SrcIp']]],
                        #           [l['SrcIp'], l['DesIp'], l['Protocol'], l['SrcPort'], l['DesPort'], l['Time'], l['Time']])
                        result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort']])

                #add the destioation Ips to the frequency dictionary,  the previous des and the current des
                if (DesIpFreq[l['DesIp']] == 0):
                    DesIpFreq[l['DesIp']] = 1
                else:
                    DesIpFreq[l['DesIp']] = DesIpFreq[l['DesIp']] + 1
                    #relatedIpDict[l['DesIp']] = relatedIpDict[l['DesIp']] + 1

        #for relatedIp in relatedIpDict:
        #    print('relatedIp = ', relatedIp, 'relatedFreq = ', relatedIpDict[relatedIp])

        groupNum = len(result) - 1
        name = ['SrcIp > DesIp', 'Protocol', 'SrcPort', 'DesPort']
        for i in range (1, groupNum+1):
            IpPairNum = len(result[i])
            if IpPairNum > 1:
                data = pd.DataFrame(columns = name, data = result[i])
                data.to_csv('/home/jin/Documents/Generated Data/data_group'+ str(i))
                #visualization(result[i],'graph_group'+ str(i))
        #print(result)
        fitdata = pd.DataFrame(columns=['fitness'], data=Flist)
        fitdata.to_csv('/home/jin/Documents/Generated Data/data_group fitness-before')
        print('output done')

        sixTlistdata = pd.DataFrame(columns=['p','c','m','r','n','a'], data=sixTlist)
        sixTlistdata.to_csv('/home/jin/Documents/Generated Data/data_group tokenNum')
        print('output done')

        Plist = []
        for j in tokenNumgroup:
            Plist.append(j.values())
        Plistdata = pd.DataFrame(columns=['start','p1','p2','p3','p4','p5','p6','p7','p8','p9','End'], data= Plist)
        Plistdata.to_csv('/home/jin/Documents/Generated Data/data_group PtokenNum')
        print('output done')

        Vlist = []
        for j in visitTgroup:
            Vlist.append(j.values())
        Vlistdata = pd.DataFrame(columns=['DNS', 'Portmap','SADMIND', 'TCP','FTP', 'FTP-Data','TELNET','UDP', 'ARP', 'ICMP'], data= Vlist)
        Vlistdata.to_csv('/home/jin/Documents/Generated Data/data_group visitedornot')
        print('output done')

if __name__ == '__main__':
    dataprocessing()