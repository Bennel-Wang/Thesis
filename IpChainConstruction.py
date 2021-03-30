import csv
import collections
import re
import pandas as pd

#In: \Raw network traffic data
#Out: \Differemt Ip chain file
#Function: Construct Ip Chain file from raw data
def IpChainConstuct():
    #initialization
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside2.csv', 'r') as f: #test for 3000 cases
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
                #pattern = re.compile(r'(.*)  >  (.*)')
                #matchObj = pattern.match(l[6])
                #if (matchObj):
                l = {'No.id': l[0], 'Time': l[1], 'SrcIp': l[2], 'DesIp': l[3], 'Protocol': l[6], 'SrcPort':l[4],'DesPort':l[5],'Len': l[7],
                         'Info': l[8]}
                #else:
                #    l = {'No.id': l[0], 'Time': l[1], 'SrcIp': l[2], 'DesIp': l[3], 'Protocol': l[6], 'SrcPort':l[4],'DesPort':l[5], 'Len': l[7],
                #         'Info': l[8]}

                #add the source Ips to the frequency dictionary, build relationship between the previous dest and the current src
                if (SrcIpFreq[l['SrcIp']] == 0):                    #SrcIp not as SrcIp before
                    if (DesIpFreq[l['SrcIp']] == 0):                #and SrcIp not as DesIp before
                        chain = chain + 1                           #new a group and add the SrcIP and DesIp to the group
                        IpChain[l['SrcIp']] = chain
                        IpChain[l['DesIp']] = IpChain[l['SrcIp']]
                        result.append([])
                        print(l['SrcIp'], ' > ', l['DesIp'], ' chain = ', IpChain[l['SrcIp']])
                        result[IpChain[l['SrcIp']]].append([l['Time'], l['SrcIp'], l['DesIp'], l['SrcPort'], l['DesPort'],  l['Protocol'], l['Info']])
                    else:                                           #but Src as Des before
                        IpChain[l['DesIp']] = IpChain[l['SrcIp']]   #link the path
                        print(l['SrcIp'], ' > ', l['DesIp'], ' chain = ', IpChain[l['SrcIp']])
                        result[IpChain[l['SrcIp']]].append([l['Time'], l['SrcIp'], l['DesIp'], l['SrcPort'], l['DesPort'],  l['Protocol'], l['Info']])
                else:                                               #SrcIp as Src before
                    IpChain[l['DesIp']] = IpChain[l['SrcIp']]
                    print(l['SrcIp'], ' > ', l['DesIp'], ' chain = ', IpChain[l['SrcIp']])
                    result[IpChain[l['SrcIp']]].append([l['Time'], l['SrcIp'], l['DesIp'], l['SrcPort'], l['DesPort'],  l['Protocol'], l['Info']])

                #add the destioation Ips to the frequency dictionary,  the previous des and the current des
                SrcIpFreq[l['SrcIp']] = SrcIpFreq[l['SrcIp']] + 1
                DesIpFreq[l['DesIp']] = DesIpFreq[l['DesIp']] + 1

        chainNum = len(result) - 1
        name = ['Time', 'SrcIp', 'DesIp', 'SrcPort','DesPort','Protocol','Info']
        for i in range (0, chainNum+1):
            IpPairNum = len(result[i])
            if IpPairNum > 1:
                data = pd.DataFrame(columns = name, data = result[i])
                data.to_csv('/home/jin/Documents/Generated Data/Ip Chain/data_chain_'+ str(i)+'.csv')

        print('output done')
