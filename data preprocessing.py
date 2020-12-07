import csv
import re
import collections

#whether the gap of two inputs is bigger the the preset value
def validTimeGap(timeFormer, timeLatter, validGap):
    if timeLatter - timeFormer > validGap:
        return False
    else:
        return True

if __name__ == '__main__':

    #initialization
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside (test).csv', 'r') as f:
        reader = csv.reader(f)
        result = []
        SrcIpDict = collections.defaultdict(int)
        DesIpDict = collections.defaultdict(int)
        relatedIpDict = collections.defaultdict(int)
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
                if (SrcIpDict[l['SrcIp']] == 0):
                    SrcIpDict[l['SrcIp']] = 1
                    if (DesIpDict[l['SrcIp']] != 0):
                        relatedIpDict[l['SrcIp']] = relatedIpDict[l['SrcIp']] + 1
                        print(l['SrcIp'], ' > ', l['DesIp'] )
                    else:
                        print('Initialize SrcIp ', l['SrcIp'], ' > ', l['DesIp'])
                else:
                    SrcIpDict[l['SrcIp']] = SrcIpDict[l['SrcIp']] + 1
                    #relatedIpDict[l['SrcIp']] = relatedIpDict[l['SrcIp']] + 1
                    print(l['SrcIp'], ' > ', l['DesIp'] )

                #add the destioation Ips to the frequency dictionary,  the previous des and the current des
                if (DesIpDict[l['DesIp']] == 0):
                    DesIpDict[l['DesIp']] = 1
                    #if (SrcIpDict[l['DesIp']] != 0):
                    #    relatedIpDict[l['DesIp']] = relatedIpDict[l['DesIp']] + 1
                else:
                    DesIpDict[l['DesIp']] = DesIpDict[l['DesIp']] + 1
                    relatedIpDict[l['DesIp']] = relatedIpDict[l['DesIp']] + 1
                    #print(l)
                    #print('DesIp:', l['DesIp'])

        for relatedIp in relatedIpDict:
            print('relatedIp = ',relatedIp, 'relatedFreq = ',relatedIpDict[relatedIp])

            #result.append(l)
        #print(result)

