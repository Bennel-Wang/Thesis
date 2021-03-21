import csv
import collections
import re
import pandas as pd

#In: \Raw network traffic data
#Out: \Differemt Ip chain file
#Function: Construct Ip Chain file from raw data
def IpChainConstuct():
    #initialization
    with open('/home/jin/Documents/LLS_DDOS 2.0 inside.csv', 'r') as f: #test for 3000 cases
        reader = csv.reader(f)
        result = []                                                     #the result of output file
        chain = -1                                                                  #current Chain number
        IpChain = collections.defaultdict(int)
        SrcIpFreq = collections.defaultdict(int)
        DesIpFreq = collections.defaultdict(int)
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
                    if (DesIpFreq[l['SrcIp']] == 0):                #and SrcIp not as DesIp before
                        chain = chain + 1                           #new a group and add the SrcIP and DesIp to the group
                        IpChain[l['SrcIp']] = chain
                        IpChain[l['DesIp']] = IpChain[l['SrcIp']]
                        result.append([])
                        print(l['SrcIp'], ' > ', l['DesIp'], ' chain = ', IpChain[l['SrcIp']])
                        result[IpChain[l['SrcIp']]].append([l['SrcIp'],  l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort'], l['Time'], l['Info']])
                    else:                                           #but Src as Des before
                        IpChain[l['DesIp']] = IpChain[l['SrcIp']]   #link the path
                        print(l['SrcIp'], ' > ', l['DesIp'], ' chain = ', IpChain[l['SrcIp']])
                        result[IpChain[l['SrcIp']]].append([l['SrcIp'], l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort'], l['Time'], l['Info']])
                else:                                               #SrcIp as Src before
                    IpChain[l['DesIp']] = IpChain[l['SrcIp']]
                    print(l['SrcIp'], ' > ', l['DesIp'], ' chain = ', IpChain[l['SrcIp']])
                    result[IpChain[l['SrcIp']]].append([l['SrcIp'], l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort'], l['Time'], l['Info']])

                #add the destioation Ips to the frequency dictionary,  the previous des and the current des
                SrcIpFreq[l['SrcIp']] = SrcIpFreq[l['SrcIp']] + 1
                DesIpFreq[l['DesIp']] = DesIpFreq[l['DesIp']] + 1

        chainNum = len(result) - 1
        name = ['SrcIp', 'DesIp', 'Protocol', 'SrcPort', 'DesPort','Time','Info']
        for i in range (0, chainNum+1):
            IpPairNum = len(result[i])
            if IpPairNum > 1:
                data = pd.DataFrame(columns = name, data = result[i])
                data.to_csv('/home/jin/Documents/Generated Data/Ip Chain/data_chain_'+ str(i)+'.csv')

        print('output done')
