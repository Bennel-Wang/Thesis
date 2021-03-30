from HelperFunction import validTimeGap
import csv
import pandas as pd
import os
import collections
import re

#Inner grouping rule based on protocol information

#Standard query 0xc9cc PTR 20.115.16.172.in-addr.arpa
#Standard query response 0xc9cc PTR 20.115.16.172.in-addr.arpa PTR mill.eyrie.af.mil NS mill.eyrie.af.mil A 172.16.115.20
def ruleDNS(protocol, info1, info2, IpSrc1, IpSrc2, IpDes1, IpDes2):
    if (protocol== 'DNS' and info1.split(' ')[2] == info2.split(' ')[3] and info1.split(' ')[3] == info2.split(' ')[4]
            and info1.split(' ')[4] == info2.split(' ')[5] and IpSrc1 == IpDes2 and IpSrc2 == IpDes1):
        return True
    else:
        return False

#V2 GETPORT Call (Reply In 2) SADMIND(100232) V:10 UDP
#V2 GETPORT Reply (Call In 1) Port:32773
def rulePortmap(protocol, info1, info2, IpSrc1,IpSrc2,IpDes1,IpDes2):
    if (protocol== 'Portmap' and info1.split(' ')[2] == 'Call' and info2.split(' ')[2] == 'Reply'
            and IpSrc1 == IpDes2 and IpSrc2 == IpDes1):
        return True
    else:
        return False

#Response: 220 mill FTP server (SunOS 5.7) ready.
#Request: user hacker2
def ruleFTP(protocol, info1, info2, IpSrc1, IpSrc2, IpDes1, IpDes2):
    if (protocol== 'FTP' and info1.split(' ')[0] == 'Response' and info2.split(' ')[0] == 'Request'
            and IpSrc1 == IpDes2 and IpSrc2 == IpDes1):
        return True
    else:
        return False
#no for FTP-DATA

#Oracle_89:a5:9f	Broadcast	ARP	60	Who has 172.16.115.20? Tell 172.16.112.50
#Oracle_89:ba:28	Oracle_89:a5:9f	ARP	60	172.16.115.20 is at 08:00:20:89:ba:28
def ruleARP(protocol, info1, info2, IpSrc1, IpSrc2, IpDes1, IpDes2):
    if (protocol == 'ARP'and info1.split(' ')[2] == (info2.split(' ')[0] +'?')
            and IpSrc1 == IpDes2 and IpDes1 =='Broadcast'):
        return True
    else:
        return False

#Echo (ping) request  id=0x0801, seq=2574/3594, ttl=253 (no response found!)
#Echo (ping) reply    id=0x0801, seq=2574/3594, ttl=64
def ruleICMP(protocol, info1, info2, IpSrc1, IpSrc2, IpDes1, IpDes2):
    if (protocol == 'ICMP' and info1.split(' ')[2] == 'request' and info2.split(' ')[2] == 'reply' and
            info1.split(' ')[4] == info2.split(' ')[4]
            and IpSrc1 == IpDes2):
        return True
    else:
        return False

#V10 proc-0 Call (Reply In 82)
#V10 proc-0 Reply (Call In 3)
def ruleSADMIND(protocol, info1, info2, IpSrc1, IpSrc2, IpDes1, IpDes2):
    if (protocol== 'SADMIND' and info1.split(' ')[2] == 'Call' and info2.split(' ')[2] == 'Reply'
            and IpSrc1 == IpDes2 and IpSrc2 == IpDes1):
        return True
    else:
        return False


protocolRuleL = ['DNS','Portmap','FTP','ARP','ICMP','SADMIND']

#In: Last grouped protocol, current protocol,last group timr, current time, last group info, current info, last group IpSrc, current IpSrc, last group IpDes, current IpDes
#Out: Grouped protocol
#Function: Group protocol
def groupProtocol(lastGroupPro, curPro, lastGroupTi, curTi, lastGroupInfo, curInfo, lastGroupIpSrc, curIpSrc, lastGroupIpDes, curIpDes):
    thresholdTi = 0.01
    if curPro == lastGroupPro.split('*')[1] and validTimeGap(lastGroupTi, curTi, thresholdTi) \
            and (curPro in protocolRuleL):
        ruleMatch = ruleDNS(curPro, lastGroupInfo, curInfo, lastGroupIpSrc, curIpSrc, lastGroupIpDes, curIpDes) or \
                    rulePortmap(curPro, lastGroupInfo, curInfo, lastGroupIpSrc, curIpSrc, lastGroupIpDes, curIpDes) or \
                    ruleFTP(curPro, lastGroupInfo, curInfo, lastGroupIpSrc, curIpSrc, lastGroupIpDes, curIpDes) or \
                    ruleARP(curPro, lastGroupInfo, curInfo, lastGroupIpSrc, curIpSrc, lastGroupIpDes, curIpDes) or \
                    ruleICMP(curPro, lastGroupInfo, curInfo, lastGroupIpSrc, curIpSrc, lastGroupIpDes, curIpDes)  or \
                    ruleSADMIND(curPro, lastGroupInfo, curInfo, lastGroupIpSrc, curIpSrc, lastGroupIpDes, curIpDes)
        if ruleMatch:
            groupPro = str((int(lastGroupPro.split('*')[0])+1)) + '*' + curPro
        else:
            groupPro = '1*' + curPro
        res = groupPro
        return res
    else:
        groupPro = '1*' + curPro
        res = groupPro
        return res

TCPlist = ['TELNET', 'FTP', 'FTP-DATA', 'RSH']

def tcpStartEnd(time1, time2, SrcIp1, SrcIp2, DesIp1, DesIp2, SrcPort1, SrcPort2, DesPort1, DesPort2, Protocol1, Protocol2):
    timeCondition = validTimeGap(time1, time2, 10)
    IpCondition = (((SrcIp1 == SrcIp2) and (DesIp1 == DesIp2)) or ((SrcIp1 == DesIp2) and (DesIp1 == SrcIp2)))
    portCondition = (((SrcPort1 == SrcPort2) and (DesPort1 == DesPort2)) or ((SrcPort1 == DesPort2) and (DesPort1 == SrcPort2)))
    protocolCondition = ((Protocol1 == 'TCP') and (Protocol2 in TCPlist))
    return timeCondition and IpCondition and portCondition and protocolCondition

#In: \Ip chain file
#Out: \Grouped file
#Function: Grouping protocol of different protocol chains according to their information
def grouping():
    name = ['Time', 'SrcIp',  'DesIp', 'SrcPort','DesPort','Protocol']
    for root, dirs, files in os.walk('/home/jin/Documents/Generated Data/Ip Chain'):
        for file in files:
            result = []
            startTCP = 0
            startTCPInfo = []
            endTCPInfo = []
            lastAppInfo = collections.defaultdict(list)
            with open('/home/jin/Documents/Generated Data/Ip Chain/' + str(file), 'r') as f:
                reader = csv.reader(f)
                for (i, l) in enumerate(reader):
                    # remove the head
                    if (i == 0):
                        continue
                    else:
                        l = {'No.id': l[0],  'Time': l[1],'SrcIp': l[2], 'DesIp': l[3],
                                 'SrcPort': l[4], 'DesPort': l[5], 'Protocol': l[6], 'Info': l[7]}

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
                data.to_csv('/home/jin/Documents/Generated Data/Grouped Chain/grouped_' + str(file))
                print(str(file))
        print('done')
    return