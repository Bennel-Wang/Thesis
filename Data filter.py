import pandas as pd
import csv
import collections
import os
import re
from HelperFunction import validTimeGap

TCPlist = ['TELNET', 'FTP', 'FTP-DATA', 'RSH']

def tcpStartEnd(time1, time2, SrcIp1, SrcIp2, DesIp1, DesIp2, SrcPort1, SrcPort2, DesPort1, DesPort2, Protocol1, Protocol2):
    timeCondition = validTimeGap(time1, time2, 10)
    IpCondition = (((SrcIp1 == SrcIp2) and (DesIp1 == DesIp2))) #or ((SrcIp1 == DesIp2) and (DesIp1 == SrcIp2)))
    portCondition = (((SrcPort1 == SrcPort2) and (DesPort1 == DesPort2))) #or ((SrcPort1 == DesPort2) and (DesPort1 == SrcPort2)))
    protocolCondition = ((Protocol1 == 'TCP') and (Protocol2 in TCPlist))
    return timeCondition and IpCondition and portCondition and protocolCondition

def dataFilter():
    name = ['Time', 'SrcIp',  'DesIp', 'SrcPort','DesPort','Protocol']
    for root, dirs, files in os.walk('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/Multi-step'):
        for file in files:
            result = []
            startTCP = 0
            startTCPInfo = []
            endTCPInfo = []
            lastAppInfo = collections.defaultdict(list)
            with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/Multi-step/' + str(file), 'r') as f:
                reader = csv.reader(f)
                for (i, l) in enumerate(reader):
                    # remove the head
                    if (i == 0):
                        continue
                    else:
                        l = {'No.id': l[0],  'Time': l[1],'SrcIp': l[2], 'DesIp': l[3],
                                 'SrcPort': l[4], 'DesPort': l[5], 'Protocol': l[6], 'Info': l[8]}

                        if l['Protocol'] == 'TCP' and re.search('SYN, ACK', l['Info'], flags=0):
                            startTCP = startTCP + 1
                            startTCPInfo.append([l['Time'],l['SrcIp'], l['DesIp'], l['SrcPort'], l['DesPort'], l['Protocol']])
                        elif (startTCP >0):
                            for i in range(0, len(startTCPInfo)):
                                [timeTCP, SrcIpTCP, DesIpTCP, SrcPortTCP, DesPortTCP, ProtocolTCP] = startTCPInfo[i]
                                if tcpStartEnd(timeTCP, l['Time'], SrcIpTCP, l['SrcIp'], DesIpTCP, l['DesIp'], SrcPortTCP, l['SrcPort'], DesPortTCP, l['DesPort'], ProtocolTCP, l['Protocol']):
                                    result.append([l['Time'], l['SrcIp'],  l['DesIp'], l['SrcPort'],l['DesPort'],l['Protocol'] + '_Begin'])
                                    startTCP = startTCP - 1
                                    startTCPInfo.pop(i)
                                    break
                        elif l['Protocol'] == 'TCP' and re.search('FIN', l['Info'], flags=0):
                            for i in range(len(endTCPInfo)-1, -1, -1):
                                [timeEndTCP, SrcIpEndTCP, DesIpEndTCP, SrcPortEndTCP, DesPortEndTCP, ProtocolEndTCP] = endTCPInfo[i]
                                if tcpStartEnd(l['Time'], timeEndTCP,  l['SrcIp'], SrcIpEndTCP, l['DesIp'], DesIpEndTCP, l['SrcPort'], SrcPortEndTCP,  l['DesPort'], DesPortEndTCP, l['Protocol'], ProtocolEndTCP):
                                    if(len(result) == 0 or ((result[-1][5] !=ProtocolEndTCP  + '_End') or (result[-1][1]!=DesIpEndTCP) or (result[-1][2]!=SrcIpEndTCP) or (result[-1][3]!=DesPortEndTCP) or (result[-1][4]!=SrcPortEndTCP))):
                                        result.append([timeEndTCP, SrcIpEndTCP, DesIpEndTCP, SrcPortEndTCP, DesPortEndTCP, ProtocolEndTCP  + '_End'])
                                    #endTCPInfo = endTCPInfo.pop(i)
                                    break
                        elif l['Protocol'] in TCPlist:
                            endTCPInfo.append([l['Time'], l['SrcIp'], l['DesIp'], l['SrcPort'], l['DesPort'], l['Protocol']])
                        elif l['Protocol'] != 'TCP' and (lastAppInfo[l['Protocol']]==[] or (not validTimeGap(lastAppInfo[l['Protocol']][0], l['Time'], 10) or ((lastAppInfo[l['Protocol']][5] !=l['Protocol']) or (lastAppInfo[l['Protocol']][1]!=l['DesIp']) or (lastAppInfo[l['Protocol']][2]!=l['SrcIp']) or (lastAppInfo[l['Protocol']][3]!=l['DesPort']) or (lastAppInfo[l['Protocol']][4]!=l['SrcPort'])))):
                            result.append([l['Time'], l['SrcIp'],  l['DesIp'], l['SrcPort'],l['DesPort'],l['Protocol']])
                            lastAppInfo[l['Protocol']] = [l['Time'], l['SrcIp'],  l['DesIp'], l['SrcPort'],l['DesPort'],l['Protocol']]

                data = pd.DataFrame(columns=name, data=result)
                data.to_csv('/home/jin/Documents/Generated Data/Multi-step/_' + str(file))
        print('done')
    return


if __name__ == '__main__':
    dataFilter()

