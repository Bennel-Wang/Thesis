import csv
import re
import collections

with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside (test).csv', 'r') as f:
    reader = csv.reader(f)
    result = []
    SrcIpDict = collections.defaultdict(int)
    DesIpDict = collections.defaultdict(int)
    relatedIpDict = collections.defaultdict(int)
    for (i,l) in enumerate(reader):
        if(i == 0):
            continue

        else:
            pattern = re.compile(r'(.*)  >  (.*)')
            matchObj = pattern.match(l[6])
            if (matchObj):
                l = {'No.id': l[0], 'Time': l[1], 'SrcIp': l[2], 'DesIp': l[3], 'Protocol': l[4], 'SrcPort':matchObj.group(1),'DesPort':matchObj.group(2).split(' ')[0],'Len': l[5],
                     'Info': l[6]}
            else:
                l = {'No.id': l[0], 'Time': l[1], 'SrcIp': l[2], 'DesIp': l[3], 'Protocol': l[4], 'SrcPort':'-','DesPort':'-', 'Len': l[5],
                     'Info': l[6]}
            if (SrcIpDict[l['SrcIp']] == 0):
                SrcIpDict[l['SrcIp']] = 1
                if (DesIpDict[l['SrcIp']] != 0):
                    relatedIpDict[l['SrcIp']] = relatedIpDict[l['SrcIp']] + 1
            else:
                SrcIpDict[l['SrcIp']] = SrcIpDict[l['SrcIp']] + 1
                relatedIpDict[l['SrcIp']] = relatedIpDict[l['SrcIp']] + 1
                #print('SrcIp:', l['SrcIp'])

            if (DesIpDict[l['DesIp']] == 0):
                DesIpDict[l['DesIp']] = 1
                if (SrcIpDict[l['DesIp']] != 0):
                    relatedIpDict[l['DesIp']] = relatedIpDict[l['DesIp']] + 1
            else:
                DesIpDict[l['DesIp']] = DesIpDict[l['DesIp']] + 1
                relatedIpDict[l['DesIp']] = relatedIpDict[l['DesIp']] + 1
                #print('DesIp:', l['DesIp'])
    for relatedIp in relatedIpDict:
        print('relatedIp = ',relatedIp, 'relatedFreq = ',relatedIpDict[relatedIp])

        #result.append(l)
    #print(result)
