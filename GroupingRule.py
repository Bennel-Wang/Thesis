from HelperFunction import validTimeGap
import csv
import pandas as pd
import os

#Inner grouping rule

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

#In: \Ip chain file
#Out: \Grouped file
#Function: Grouping protocol of different protocol chains according to their information
def grouping():
    name = ['Protocol', 'Time']
    for root, dirs, files in os.walk('/home/jin/Documents/Generated Data/Ip Chain'):
        for file in files:
            res = []
            with open('/home/jin/Documents/Generated Data/Ip Chain/' + str(file), 'r') as f:
                lastRecord = ['SrcIp', 'DesIp', '1*Protocol', 'Time', 'Info']
                reader = csv.reader(f)
                for (i, l) in enumerate(reader):
                    # remove the head
                    if (i == 0):
                        continue
                    else:
                        l = {'No.id': l[0],  'SrcIp': l[1], 'DesIp': l[2], 'Protocol': l[3],
                                 'SrcPort': l[4], 'DesPort': l[5],  'Time': l[6], 'Info': l[7]}
                        #print(l[7])
                        groupedPro = groupProtocol(lastRecord[2], l['Protocol'], lastRecord[3], l['Time'], lastRecord[4], l['Info'], lastRecord[0], l['SrcIp'], lastRecord[1], l['DesIp'])
                        if ((int(groupedPro.split('*')[0]) == (int(lastRecord[2].split('*')[0])+1)) and (groupedPro.split('*')[1] == lastRecord[2].split('*')[1])):
                            res[-1][0] = groupedPro
                        else:
                            res.append([groupedPro, l['Time']])
                        lastRecord = [l['SrcIp'], l['DesIp'], groupedPro, l['Time'],l['Info']]
                data = pd.DataFrame(columns=name, data=res)
                data.to_csv('/home/jin/Documents/Generated Data/Grouped Chain/grouped_' + str(file))
        print('done')
    return
