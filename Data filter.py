import pandas as pd
import csv
import collections
import os
import re
from HelperFunction import validTimeGap
def dataFilter():
    #initialization
    for root, dirs, files in os.walk('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/Multi-step'):
        for file in files:
            with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/Multi-step/' + str(file), 'r') as f:
                reader = csv.reader(f)
                startTCP = False
                lastTime = collections.defaultdict(str)
                lastProtocol = collections.defaultdict(str)
                #lastTwoProtocol = collections.defaultdict(str)
                result = []
                for (j, l) in enumerate(reader):
                    if (j == 0):
                        continue
                    else:
                        l = {'Protocol': l[4], 'Time': l[1],'Info':l[6]}
                        if l['Protocol'] == 'TCP' and re.search('SYN', l['Info'], flags=0):
                            startTCP = True
                        elif startTCP == True and (l['Protocol'] == 'TELNET' or l['Protocol'] == 'RSH' or l['Protocol'] == 'FTP' or l['Protocol'] == 'FTP-DATA'):
                            l['Info'] = 'TCP Begin'
                            result.append(l)
                            startTCP = False
                        elif l['Protocol'] != 'TCP' and lastTime[l['Protocol']] == '':
                            result.append(l)
                        elif l['Protocol'] != 'TCP' and not validTimeGap(lastTime[l['Protocol']], l['Time'], 2000):
                            result.append(l)
                        elif l['Protocol'] == 'TCP' and re.search('FIN', l['Info'], flags=0) and (lastProtocol['Protocol'] == 'TELNET' or lastProtocol['Protocol'] == 'RSH' or lastProtocol['Protocol'] == 'FTP' or lastProtocol['Protocol'] == 'FTP-DATA'):
                            lastProtocol['Info'] = 'TCP End'
                            result.append(lastProtocol)
                        lastProtocol = l
                        lastTime[l['Protocol']] = l['Time']
                if len(result) > 0:
                    name = ['Protocol', 'Time','Info']
                    data = pd.DataFrame(columns=name, data=result)
                    data.to_csv('/home/jin/Documents/Generated Data/Multi-step/'+ str(file))
                    print('Multi-step grouping done')

if __name__ == '__main__':
    dataFilter()

