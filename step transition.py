import csv

IPsweep_A = {'2*ICMP':{'Pre':['Start'],'Pos':['End']}, '1*SA':{'Pre':['End'], 'Pos':['Start']}}
IPsweep_P = {'Start':0,'End': 0}

DAESAD_A = {'2*Portmap':{'Pre':['Start'],'Pos':['P1']},'2*SADMIND':{'Pre':['P1'],'Pos':['P2']},
            '1*SADMIND':{'Pre':['P3'],'Pos':['P4']}, '1*ICMP':{'Pre':['P4'],'Pos':['End']},
            '1*SA':{'Pre':['P2'], 'Pos':['Start']}, '2*SA':{'Pre':['P2'], 'Pos':['P3']},
            '3*SA':{'Pre':['End'], 'Pos':['P3']}, '4*SA':{'Pre':['End'], 'Pos':['Start']}}
DAESAD_P = {'Start':0, 'P1':0, 'P2':0, 'P3':0, 'P4':0, 'End':0}

BreakSAD_A = {'2*Portmap':{'Pre':['Start'],'Pos':['P1']}, '1*SADMIND':{'Pre':['P1'],'Pos':['End']},
            '1*SA':{'Pre':['End'],'Pos':['Start']}}
BreakSAD_P = {'Start':0, 'P1':0,'End':0}

InsDDoS_A = {'4*TCP':{'Pre':['P2'],'Pos':['End']},'3*TCP':{'Pre':['Start'],'Pos':['P1']},
             '1*RSH':{'Pre':['P1'],'Pos':['P2']},'1*SA':{'Pre':['P2'],'Pos':['P1']},
           '2*SA':{'Pre':['End'],'Pos':['Start']}}
InsDDoS_P = {'Start':0, 'P1':0, 'P2':0, 'End':0}

LauDDoS_A = {'4*TCP':{'Pre':['P2','P4'],'Pos':['End']},'3*TCP':{'Pre':['Start'],'Pos':['P1','P3']},
             '1*TCP':{'Pre':['P1'],'Pos':['P2']},'1*TELNET':{'Pre':['P3'],'Pos':['P4']},
             '1*SA':{'Pre':['P2'],'Pos':['P1']},'2*SA':{'Pre':['P4'],'Pos':['P3']}}
LauDDoS_P = {'Start':0, 'P1':0, 'P2':0, 'P3':0, 'P4':0, 'End':0}

DNSServer_A = {'1*DNS':{'Pre':['Start'],'Pos':['End']}, '1*SA':{'Pre':['End'], 'Pos':['Start']}}
DNSServer_P = {'Start':0, 'End': 0}

FTPUpload_A = {'4*TCP':{'Pre':['P3'],'Pos':['End']},'3*TCP':{'Pre':['Start'],'Pos':['P1']}, '1*TCP':{'Pre':['P1'],'Pos':['P2']},
               '2*FTP-Data':{'Pre':['P2'],'Pos':['P3']}, '2*FTP':{'Pre':['P1'],'Pos':['P3']},
               '1*SA':{'Pre':['P3'],'Pos':['P1']},'2*SA':{'Pre':['End'],'Pos':['Start']},}
FTPUpload_P = {'Start':0, 'P1':0, 'P2':0, 'P3':0, 'End':0}

Attack0_A = [IPsweep_A.copy(), DAESAD_A.copy(), BreakSAD_A.copy(), InsDDoS_A.copy(), LauDDoS_A.copy()]
Attack0_P = [IPsweep_P.copy(), DAESAD_P.copy(), BreakSAD_P.copy(), InsDDoS_P.copy(), LauDDoS_P.copy()]

Attack1_A = [DNSServer_A.copy(), BreakSAD_A.copy(), FTPUpload_A.copy(), LauDDoS_A.copy(), BreakSAD_A.copy(), FTPUpload_A.copy(), LauDDoS_A.copy()]
Attack1_P = [DNSServer_P.copy(), BreakSAD_P.copy(), FTPUpload_P.copy(), LauDDoS_P.copy(), BreakSAD_P.copy(), FTPUpload_P.copy(), LauDDoS_P.copy()]

AttackList = [[Attack0_A,Attack1_P], [Attack1_A,Attack1_P]]

#In: 4 tokens list
#Out: improved fitness value
#Function: calculate fitness
def calFitness(fourToken):
    x = 1                #for inner loop improvement parameter
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
    Fthreshold = 0.7            #fitness threshold for step transition
    if fitness > Fthreshold:
        return True
    else:
        return False

#In: Attack list, two dimensional list of step for each attack and group, Protocol, group number for this protocol
#Out: list of transitting attack the protocol belongs to, false for not in all attack pattern
#Function: whether the protocol belongs to activity of any transitting attack pattern
def isProPattern(attackL,stepL,Protocol,group):
    for (i,attack) in enumerate(attackL):
        for prot in attack[stepL[group][i]][0]:
            if prot == Protocol:
                return True
    else:
        return False

#In: protocol list for each group, last appeared time list for each group, time for this protocol, protocol
#    Attack list, two dimensional list of step for each attack and group, three dimensional list for four token of group and attack,group for this protocol
#Out: /
#Function: group the protocol into protocol list for each group, if the interval is bigger than threshold, let protocol list flow and let step transits.
def processFlow (proL,lastAppT,curT,Protocol,attackL,stepL,fourTokenL,group):
    thresholdT = 2                                                  #minimum time threshold to split two step
    stepTran = False                                                #whether step transition has been performed for any attack
    if isProPattern(attackL,stepL,Protocol,group):                  #protocol belong to at least one of the transitting attack pattern
        if (float(curT) - float(lastAppT[group])) < thresholdT :    #in the interval
            proL[group].append(Protocol)
        else:
            for (i,attack) in enumerate(attackL):
                fitness = protoListFlow(proL[group],fourTokenL[group][i],attack,stepL[group][i])
                if stepTransit(fitness):
                    proL[group]= [Protocol]
                    stepL[group][i] = stepL[group][i] + 1
                    stepTran = True
            if not stepTran:
                proL[group].append(Protocol)
    return


#In: two dimensional Protocol list for each group of each attack, three dimensional four token list for each group of each attack,group number
#Out: fitness of the protocol list for the attack
#Function: calculate the four token of the list of protocol
def protoListFlow (proL, fourToken,attack, step):
    for protocol in proL:
        tokenFlow(protocol, attack, fourToken, step)
    fitness = calFitness(fourToken)
    return fitness

#In:petri net, pos node, four token list
#Out:/revised net
#Function:consume/miss one token flow, start not miss
def consumeToken(net_P,node,fourToken):
    if net_P[node] > 0:
        net_P[node] = net_P[node] - 1
        fourToken[1] = fourToken[1] + 1
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
        if p != 'Start':
            fourToken[3] = fourToken[3] + net_P[p]
    return

#In: protocol, attack, one dimensional fourToken number list, step of the attack
#Out:/ modified the new four token
#Function:flow one protocol
def tokenFlow(protocol, attack, fourToken, step):
    net_A = attack[step][0]
    net_P = attack[step][1]
    if protocol not in net_A:
        return
    else:
        for preP in net_A[protocol]['Pre']:
            for act in net_A:
                if act.split('*')[1] == 'SA' and preP == net_A[act]['Pos']:
                    tokenFlow(act, attack, fourToken, step)
            consumeToken(net_P, preP, fourToken)
        for posP in net_A[protocol]['Pos']:
            produceToken(net_P, posP, fourToken)
        return

def dataprocessing():
    with open('/home/jin/Documents/LLS_DDOS 1.0 inside.csv', 'r') as f:
        reader = csv.reader(f)
        result = [['SrcIp > DesIP', 'Protocol', 'SrcPort', 'DesPort', 'Time']]  # the result of output file





if __name__ == '__main__':
    dataprocessing()
