import csv
import re
import collections
import pandas as pd

#whether the gap of two inputs is bigger the the preset value
def validTimeGap(timeFormer, timeLatter, validGap):
    if float(timeLatter) - float(timeFormer) > validGap:
        return False
    else:
        return True

if __name__ == '__main__':

    #initialization
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside (test).csv', 'r') as f:
        reader = csv.reader(f)
        result = [['Ip', 'Time', 'Type', 'attack tree group']]
        group = 0
        validInterval = 0.1
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
                        #result.append([['Ip', 'Time', 'Type']])
                        result.append([])
                        result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'], l['Time'], l['Info']])
                    else:                                           #but Src as Des before
                        #relatedIpDict[l['SrcIp']] = relatedIpDict[l['SrcIp']] + 1
                        if (validTimeGap(IpLastTime[l['SrcIp']], l['Time'], validInterval)):    #if the time interval between Ip current and last appearance, link the path
                            IpLastTime[l['SrcIp']] = l['Time']
                            IpLastTime[l['DesIp']] = l['Time']
                            IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                            print(l['SrcIp'], ' > ', l['DesIp'],  ' time = ', l['Time'], l['Info'], ' group = ', IpGroup[l['SrcIp']])
                            result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'], l['Time'], l['Info'] ])
                        else:                                                       #otherwise, break and create a new path
                            IpLastTime[l['SrcIp']] = l['Time']
                            IpLastTime[l['DesIp']] = l['Time']
                            group = group + 1  # new a group and add the SrcIP and DesIp to the group
                            IpGroup[l['SrcIp']] = group
                            IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                            print('Initialize SrcIp ', l['SrcIp'], ' > ', l['DesIp'], ' time = ', l['Time'], l['Info'],
                                  'Attack tree group = ', IpGroup[l['SrcIp']])
                            # result.append([['Ip', 'Time', 'Type']])
                            result.append([])
                            result[IpGroup[l['SrcIp']]].append([l['SrcIp'] + ' > ' + l['DesIp'], l['Time'], l['Info']])
                else:                                               #SrcIp as Src before
                    if (validTimeGap(IpLastTime[l['SrcIp']], l['Time'], validInterval)):   #if the time interval between Ip current and last appearance, link the path
                        IpLastTime[l['SrcIp']] = l['Time']
                        IpLastTime[l['DesIp']] = l['Time']
                        SrcIpFreq[l['SrcIp']] = SrcIpFreq[l['SrcIp']] + 1
                        IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                        print(l['SrcIp'], ' > ', l['DesIp'], ' time = ', l['Time'], l['Info'], ' group = ', IpGroup[l['SrcIp']])
                        result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'], l['Time'], l['Info']])
                    else:                                                       # otherwise, break and create a new path
                        IpLastTime[l['SrcIp']] = l['Time']
                        IpLastTime[l['DesIp']] = l['Time']
                        SrcIpFreq[l['SrcIp']] = SrcIpFreq[l['SrcIp']] + 1
                        group = group + 1  # new a group and add the SrcIP and DesIp to the group
                        IpGroup[l['SrcIp']] = group
                        IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                        print('Initialize SrcIp ', l['SrcIp'], ' > ', l['DesIp'], ' time = ', l['Time'], l['Info'],
                              'Attack tree group = ', IpGroup[l['SrcIp']])
                        # result.append([['Ip', 'Time', 'Type']])
                        result.append([])
                        result[IpGroup[l['SrcIp']]].append([l['SrcIp'] + ' > ' + l['DesIp'], l['Time'], l['Info']])

                #add the destioation Ips to the frequency dictionary,  the previous des and the current des
                if (DesIpFreq[l['DesIp']] == 0):
                    DesIpFreq[l['DesIp']] = 1
                else:
                    DesIpFreq[l['DesIp']] = DesIpFreq[l['DesIp']] + 1
                    #relatedIpDict[l['DesIp']] = relatedIpDict[l['DesIp']] + 1

        #for relatedIp in relatedIpDict:
        #    print('relatedIp = ', relatedIp, 'relatedFreq = ', relatedIpDict[relatedIp])

        groupNum = len(result) - 1
        name = ['Ip', 'Time', 'Info']
        for i in range (1, groupNum+1):
            IpPairNum = len(result[i])
            if IpPairNum > 1:
                data = pd.DataFrame(columns = name, data = result[i])
                data.to_csv('/home/jin/Documents/Generated Data/data_group'+ str(i))
        #print(result)
        print('output done')

