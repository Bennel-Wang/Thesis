import collections
import csv
import re
import pandas as pd

IPsweep_A = {'2*ICMP':{'Pre':['Start'],'Pos':['End']}, '1*SA':{'Pre':['End'], 'Pos':['Start']}}
IPsweep_P = {'Start':0,'End': 0}

DAESAD_A = {'1*Portmap':{'Pre':['Start'],'Pos':['P1']}, '1*ICMP':{'Pre':['P1'],'Pos':['End']},
            '1*SA':{'Pre':['End'],'Pos':['Start']}}
DAESAD_P = {'Start':0, 'P1':0,'End':0}

BreakSAD_A = {'2*Portmap':{'Pre':['Start'],'Pos':['P1']}, '1*SADMIND':{'Pre':['P1'],'Pos':['End']},
            '1*SA':{'Pre':['End'],'Pos':['Start']}}
BreakSAD_P = {'Start':0, 'P1':0,'End':0}

InsDDoS_A = {'1*RSH':{'Pre':['Start'],'Pos':['End']},'2*RSH':{'Pre':['Start'],'Pos':['End']},
             '3*RSH':{'Pre':['Start'],'Pos':['End']},'4*RSH':{'Pre':['Start'],'Pos':['End']},'5*RSH':{'Pre':['Start'],'Pos':['End']},
             '1*SA':{'Pre':['End'],'Pos':['Start']}}
InsDDoS_P = {'Start':0, 'End':0}

#LauDDoS_A = {'3*TCP':{'Pre':['Start'],'Pos':['P1','P3']},
#             '1*TCP':{'Pre':['P1'],'Pos':['P2']},'1*TELNET':{'Pre':['P3'],'Pos':['P4']},'4*TCP':{'Pre':['P2','P4'],'Pos':['End']},
#             '1*SA':{'Pre':['P2'],'Pos':['P1']},'2*SA':{'Pre':['P4'],'Pos':['P3']}}
#LauDDoS_P = {'Start':0, 'P1':0, 'P2':0, 'P3':0, 'P4':0, 'End':0}

LauDDoS_A = {'1*TELNET':{'Pre':['Start'],'Pos':['End']},'2*TELNET':{'Pre':['Start'],'Pos':['End']},'3*TELNET':{'Pre':['Start'],'Pos':['End']},
               '1*SA':{'Pre':['End'],'Pos':['Start']}}
LauDDoS_P = {'Start':0,'End': 0}

DNSServer_A = {'2*DNS':{'Pre':['Start'],'Pos':['End']}, '1*SA':{'Pre':['End'], 'Pos':['Start']}}
DNSServer_P = {'Start':0, 'End': 0}

#FTPUpload_A = {'3*TCP':{'Pre':['Start'],'Pos':['P1']}, '1*TCP':{'Pre':['P1'],'Pos':['P2']},
#               '2*FTP-DATA':{'Pre':['P2'],'Pos':['P3']},
#               '1*SA':{'Pre':['P3'],'Pos':['P1']},'2*SA':{'Pre':['End'],'Pos':['Start']},'4*TCP':{'Pre':['P3'],'Pos':['End']}}
#FTPUpload_P = {'Start':0, 'P1':0, 'P2':0, 'P3':0, 'End':0}
FTPUpload_A = {'1*TCP':{'Pre':['Start'],'Pos':['P1']},'2*FTP-DATA':{'Pre':['P1'],'Pos':['End']},'1*SA':{'Pre':['End'], 'Pos':['Start']}}
FTPUpload_P = {'Start':0, 'P1':0, 'End':0}



Attack0_A = [IPsweep_A, DAESAD_A, BreakSAD_A, InsDDoS_A, LauDDoS_A]
Attack0_P = [IPsweep_P.copy(), DAESAD_P.copy(), BreakSAD_P.copy(), InsDDoS_P.copy(), LauDDoS_P.copy()]

Attack1_A = [DNSServer_A, BreakSAD_A, FTPUpload_A, LauDDoS_A, FTPUpload_A, LauDDoS_A]
Attack1_P = [DNSServer_P.copy(), BreakSAD_P.copy(), FTPUpload_P.copy(), LauDDoS_P.copy(), FTPUpload_P.copy(), LauDDoS_P.copy()]

AttackList = [[Attack0_A, Attack0_P], [Attack1_A,Attack1_P]]

#In: 4 tokens list
#Out: improved fitness value
#Function: calculate fitness
def calFitness(fourToken):
    x = 0.45             #for inner loop improvement parameter
    p = fourToken[0]     #produced
    c = fourToken[1]     #consumed
    m = fourToken[2]     #missed
    r = fourToken[3]     #remained
    fitness =  1/2 * (1 - ((m+x)/(c+x))) + 1/2 * (1 - ((r+x)/(p+x)))    #for numerator and denominator all 0, fitness = 0
    return fitness


#In: fitness
#Out: transit or not
#Function: whether to transit to next step
def stepTransit (fitness):
    Fthreshold = 0.8            #fitness threshold for step transition
    if fitness > Fthreshold:
        return True
    else:
        return False

#In: time in string, validGap in float
#out: T/F for valid gap
#Function: whether the gap between two time less than the preset value
def validTimeGap(timeFormer, timeLatter, validGap):
    if float(timeLatter) - float(timeFormer) > validGap:
        return False
    else:
        return True

#In: Attack list, two dimensional list of step for each attack and group, Protocol, group number for this protocol
#Out: list of transitting attack the protocol belongs to, false for not in all attack pattern
#Function: whether the protocol belongs to activity of any transitting attack pattern
def isProPattern(attackL,stepL,Protocol,group):
    for (i,attack) in enumerate(attackL):
        for prot in attack[0][stepL[group][i]]:
            if prot == Protocol:
                return True
    else:
        return False

#In: protocol list for each group, last appeared time list for each group, time for this protocol, protocol
#    Attack list, two dimensional list of step for each attack and group, three dimensional list for four token of group and attack,group for this protocol
#Out: /
#Function: group the protocol into protocol list for each group, if the interval is bigger than threshold, let protocol list flow and let step transits.
def processFlow (proL,lastGroupT,groupT,groupProtocol,attackL,stepL,fourTokenL,group):
    thresholdT = 20                                                  #minimum time threshold to split two step
    stepTran = False                                                #whether step transition has been performed for any attack
    #if isProPattern(attackL,stepL,Protocol,group):                  #protocol belong to at least one of the transitting attack pattern
    if validTimeGap(lastGroupT, groupT, thresholdT) and isProPattern(attackL,stepL,groupProtocol,group):
        if groupProtocol != '1*Begin':
            proL[group].append(groupProtocol)
    else:
        for (i,attack) in enumerate(attackL):
            fourTokenL[group][i] = [0,0,0,0]
            fitness = protoListFlow(proL[group],fourTokenL[group][i],attack,stepL[group][i],group,i)
            #if group == 24 and i == 1:
            #    print(proL[group])
            #    print(fourTokenL[group][i])
            #    print('group = ', group, 'step=', stepL[group][i] + 1,'attackNum=',i, 'fitness=', fitness, 'group time=', lastGroupT)
            if stepTransit (fitness) and stepL[group][i] < len(attack[1])-1:
                #if group == 24 and i == 1:
                print(proL[group])
                print(fourTokenL[group][i])
                print('group = ', group, 'step=', stepL[group][i] + 1, 'attackNum=', i, 'fitness=', fitness,
                          'group time=', lastGroupT)
                print('--------------')
                proL[group]= [groupProtocol]
                stepL[group][i] = stepL[group][i] + 1
                stepTran = True
        if not stepTran and isProPattern(attackL,stepL,groupProtocol,group):
            if groupProtocol != '1*Begin':
                proL[group].append(groupProtocol)
    return


#In: two dimensional Protocol list for each group of each attack, three dimensional four token list for each group of each attack,group number
#Out: fitness of the protocol list for the attack
#Function: calculate the four token of the list of protocol
def protoListFlow (proL, fourToken, attack, step,group,attackNum):
    net_A = attack[0][step]
    net_P = attack[1][step].copy()
    for protocol in proL:
        tokenFlow(protocol, net_A, net_P, fourToken, step)
    fitness = calFitness(fourToken)
    if fitness>0.8:
        print(net_P,fourToken)
    return fitness

#In:petri net, pos node, four token list
#Out:/revised net
#Function:consume/miss one token flow, start not miss
def consumeToken(net_P,node,fourToken):
    if net_P[node] > 0:
        net_P[node] = net_P[node] - 1
        fourToken[1] = fourToken[1] + 1  # consume 1 token
    elif node != 'Start':
        fourToken[2] = fourToken[2] + 1  # miss 1 token
        fourToken[1] = fourToken[1] + 1  # consume 1 token
    else:
        fourToken[1] = fourToken[1] + 1  # consume 1 token
    return

# In:petri net, pos node, four token list
# Out:/revised net
# Function:produce/remain one token flow, end not remain
def produceToken(net_P,node,fourToken):
    net_P[node] = net_P[node] + 1
    fourToken[0] = fourToken[0] + 1
    fourToken[3] = 0
    for p in net_P:
        if p != 'End':
            fourToken[3] = fourToken[3] + net_P[p]
    return

#In: protocol, attack, one dimensional fourToken number list, step of the attack
#Out:/ modified the new four token
#Function:flow one protocol
def tokenFlow(protocol, net_A, net_P, fourToken, step):
    if protocol not in net_A:
        return
    else:
        for preP in net_A[protocol]['Pre']:
            for act in net_A:
                if act.split('*')[1] == 'SA' and preP == net_A[act]['Pos'] and net_P[preP] <= 0:  #SA only execute when miss
                    tokenFlow(act, net_A, net_P, fourToken, step)        #SA can also miss/remain
            #print(net_P, fourToken, step)
            consumeToken(net_P, preP, fourToken)
        for posP in net_A[protocol]['Pos']:
            #print(posP,protocol,net_P,net_A,step)
            produceToken(net_P, posP, fourToken)
        return

#In: protocol list for each group, current protocol, attack pattern list,
#    two dimensional list of step for each attack and group, three dimensional list for four token of group and attack,group for this protocol
#    current time, last protocol for that group,last appeared time list for each group, time for this protocol, protocol group pattern
#Out: protocol inner grouping result(last protocol)
#Function: get the last protocol, execute the process flow
def protocolProcessing(proL, protocol, attackL, stepL, fourTokenL, time, lastGProtocol, lastAppT, groupT, lastGroupT, group):
    thresholdT = 0.0035
    if protocol == lastGProtocol.split('*')[1] and validTimeGap(lastAppT[group],time,thresholdT):
        res = str((int(lastGProtocol.split('*')[0])+1)) + '*' + protocol
        groupT[group] = time
    else:
        processFlow(proL, lastGroupT[group], groupT[group], lastGProtocol, attackL, stepL, fourTokenL, group)
        lastGroupT[group] = groupT[group]
        groupT[group] = time
        res = '1*' + protocol
    return res

#Parameter Description: protocolList[group], attackList[attack number][net_A/P][step],stepList[group][attack number],
# fourTokenList[group][attack number], lastProtocol[group], lastAppearTime[group],group,result[group][parameter list]
#
def dataprocessing():
    #initialization
    with open('/home/jin/Documents/LLS_DDOS 2.0 inside.csv', 'r') as f: #test for 3000 cases
        reader = csv.reader(f)
        result = []                                                     #the result of output file
        protocolList = []
        stepList = []
        fourTokenList = []
        group = -1                                                                  #current group number
        IpGroup = collections.defaultdict(int)
        SrcIpFreq = collections.defaultdict(int)
        DesIpFreq = collections.defaultdict(int)
        lastProtocol = collections.defaultdict(str)
        lastTime  = collections.defaultdict(str)
        groupT = []
        lastGroupT = []
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

                #print(l['Time'])
                #add the source Ips to the frequency dictionary, build relationship between the previous dest and the current src
                if (SrcIpFreq[l['SrcIp']] == 0):                    #SrcIp not as SrcIp before
                    if (DesIpFreq[l['SrcIp']] == 0):                #and SrcIp not as DesIp before
                        group = group + 1                           #new a group and add the SrcIP and DesIp to the group
                        IpGroup[l['SrcIp']] = group
                        IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                        result.append([])
                        protocolList.append([])
                        stepList.append([0]*len(AttackList))
                        fourTokenList.append([[0,0,0,0]]*len(AttackList))
                        groupT.append('0.0')
                        lastGroupT.append('0.0')
                        lastTime[IpGroup[l['SrcIp']]] = '0.0'
                        lastProtocol[IpGroup[l['SrcIp']]] ='1*Begin'
                        lastProtocol[IpGroup[l['SrcIp']]] = protocolProcessing(protocolList, l['Protocol'], AttackList, stepList, fourTokenList, l['Time'], lastProtocol[IpGroup[l['SrcIp']]], lastTime,
                                           groupT, lastGroupT,IpGroup[l['SrcIp']])
                        #print(stepList[IpGroup[l['SrcIp']]])
                        lastTime[IpGroup[l['SrcIp']]] = l['Time']
                        #print('Initialize SrcIp ', l['SrcIp'], ' > ', l['DesIp'], ' time = ', l['Time'],  l['Info'], 'Attack tree group = ', IpGroup[l['SrcIp']])
                        result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort'], l['Time']])
                    else:                                           #but Src as Des before
                        IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]   #link the path
                        #print(l['SrcIp'], ' > ', l['DesIp'],  ' time = ', l['Time'], l['Info'], ' group = ', IpGroup[l['SrcIp']])
                        result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort'], l['Time']])
                        lastProtocol[IpGroup[l['SrcIp']]] = protocolProcessing(protocolList, l['Protocol'], AttackList, stepList, fourTokenList, l['Time'], lastProtocol[IpGroup[l['SrcIp']]], lastTime,
                                           groupT, lastGroupT,IpGroup[l['SrcIp']])
                        #print(stepList[IpGroup[l['SrcIp']]])
                        lastTime[IpGroup[l['SrcIp']]] = l['Time']
                else:                                               #SrcIp as Src before
                    IpGroup[l['DesIp']] = IpGroup[l['SrcIp']]
                    #print(l['SrcIp'], ' > ', l['DesIp'], ' time = ', l['Time'], l['Info'], ' group = ', IpGroup[l['SrcIp']])
                    result[IpGroup[l['SrcIp']]].append([l['SrcIp'] +' > '+ l['DesIp'],  l['Protocol'], l['SrcPort'], l['DesPort'], l['Time']])
                    lastProtocol[IpGroup[l['SrcIp']]] = protocolProcessing(protocolList, l['Protocol'], AttackList,
                                                                           stepList, fourTokenList, l['Time'],
                                                                           lastProtocol[IpGroup[l['SrcIp']]], lastTime,
                                                                           groupT, lastGroupT, IpGroup[l['SrcIp']])
                    #print(stepList[IpGroup[l['SrcIp']]])
                    lastTime[IpGroup[l['SrcIp']]]  = l['Time']

                #add the destioation Ips to the frequency dictionary,  the previous des and the current des
                SrcIpFreq[l['SrcIp']] = SrcIpFreq[l['SrcIp']] + 1
                DesIpFreq[l['DesIp']] = DesIpFreq[l['DesIp']] + 1

        stepdata = pd.DataFrame(columns=['attack0','attack1'], data=stepList)
        stepdata.to_csv('/home/jin/Documents/Generated Data/data_group step')
        print('output done')

        groupNum = len(result) - 1
        name = ['SrcIp > DesIp', 'Protocol', 'SrcPort', 'DesPort','Time']
        for i in range (0, groupNum+1):
            IpPairNum = len(result[i])
            if IpPairNum > 1:
                data = pd.DataFrame(columns = name, data = result[i])
                data.to_csv('/home/jin/Documents/Generated Data/data_group'+ str(i))

        #sixTlistdata = pd.DataFrame(columns=['p','c','m','r','n','a'], data=sixTlist)
        #sixTlistdata.to_csv('/home/jin/Documents/Generated Data/data_group tokenNum')
        print('output done')




if __name__ == '__main__':
    dataprocessing()
