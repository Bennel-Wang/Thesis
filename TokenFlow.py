from HelperFunction import validTimeGap
import os
import csv
import pandas as pd
from PetriNetModel import transitionSet
from PetriNetModel import AttackList

#In: 4 tokens list, log number
#Out: improved fitness value
#Function: calculate fitness
def calFitness(fourToken, logNum):
    const = 0.05 * logNum
    p = fourToken[0]     #produced
    c = fourToken[1]     #consumed
    m = fourToken[2]     #missed
    r = fourToken[3]     #remained
    fitness =  1/2 * (1 - ((m+const)/(c+const))) + 1/2 * (1 - ((r+const)/(p+const)))    #for numerator and denominator all 0, fitness = 0
    return fitness


#In:petri net, node, current time,  four token list, token consume deadline, place weighting factor
#Out:/revised net
#Function:consume/miss w token flow
def consumeToken(net_P, node, time, fourToken, cddl = float("inf"), w = '1'):
    # silent activity
    if (len(net_P[node]) > 0) and validTimeGap(time, net_P[node][0], 0):        #have token already been produced
        for (i, tokenPT) in enumerate(net_P[node]):
            if validTimeGap(tokenPT, time, cddl):   #within the deadline
                net_P[node].pop(i)
                fourToken[1] = fourToken[1] + float(w)  # consume w token
                break
        else:   #exceed the deadline
            fourToken[2] = fourToken[2] + float(w)  # miss w token
            fourToken[1] = fourToken[1] + float(w)  # consume w token
    else:
        fourToken[2] = fourToken[2] + float(w)  # miss w token
        fourToken[1] = fourToken[1] + float(w)  # consume w token
    return

# In:petri net, node, current time, four token list, token produce delay, place weighting factor
# Out:/revised net
# Function:produce/remain one token flow, end not remain
def produceToken(net_P, node, time, fourToken, pd = float('0'), w = '1'):
    net_P[node].append(str(float(time)+float(pd)))       #append the produced time
    fourToken[0] = fourToken[0] + float(w)
    fourToken[3] = fourToken[0] - fourToken[1] + fourToken[2]
    return

#In: PetriNet_A2, protocol
#Out: list of preset of [place, consumption delay]
#Function: finding the pre set of a protocol
def presetPlace(petriNet_A1, protocol):
    res = []
    for arcFrom in petriNet_A1:
        if arcFrom[1] == protocol:
            res.append([arcFrom[0], arcFrom[2]])
    return res

# In: PetriNet_A2, protocol
# Out: list of postset of [place, production delay]
# Function: finding the post set of a protocol
def postsetPlace(petriNet_A2, protocol):
    res = []
    for arcTo in petriNet_A2:
        if arcTo[0] == protocol:
            res.append([arcTo[1], arcTo[2]])
    return res


# In: petriNet_T, petriNet_P, petriNet_A1, petriNet_A2, fourToken, protocol, time
# Out: \
# Function: fire a protocol
def fireProtocol(petriNet_T, petriNet_P, petriNet_A1, petriNet_A2, fourToken, protocol, time):
    protocolPreset = presetPlace(petriNet_A1, protocol)
    protocolPostset = postsetPlace(petriNet_A2, protocol)
    for [preplace, cddl] in protocolPreset:
        if len(petriNet_P[preplace]) == 0:
            for pro in petriNet_T:
                if pro.split('*')[1] == 'SA':
                    for [pla,_ ] in postsetPlace(petriNet_A2, pro):
                        if pla == preplace:
                            fireProtocol(petriNet_T, petriNet_P, petriNet_A1, petriNet_A2, fourToken, pro, time)
        consumeToken(petriNet_P, preplace, time, fourToken, cddl, preplace.split('*')[0])
    for [postPlace, pd] in protocolPostset:
        produceToken(petriNet_P, postPlace, time, fourToken, pd, postPlace.split('*')[0])
    return




#In: Protocol list of corresponding Ip chains to calculate fitness, four tokens list of traget chain, attacklist to detect, two dimensional step list, chain number
#Out: two dimensional fitness list of the protocol list for the attack
#Function: calculate the fitness of each attack for the protocol list
def protoListFlow(petriNet_T, petriNet_P, petriNet_A1, petriNet_A2, petriNet_L, fourToken, inputSeq):
    for p in petriNet_P:
        if p.split('*')[1] == 'Start':
            #print((petriNet_P, p, '0', fourToken, '0', p.split('*')[0]))
            produceToken(petriNet_P, p, '0', fourToken, '0', p.split('*')[0])
            break
    for [protocol, time] in inputSeq:
        fireProtocol(petriNet_T, petriNet_P, petriNet_A1, petriNet_A2, fourToken, protocol, time)
    consumeToken(petriNet_P, '1*End', time, fourToken, float("inf"), '1')
    fitness = calFitness(fourToken, petriNet_L)
    return fitness


def tokenReplay():
    for root, dirs, files in os.walk('/home/jin/Documents/Generated Data/Grouped Chain'):
        attackSeq = []
        for file in files:
            stepNum = 0
            for (i, attack) in enumerate(AttackList):
                inputSeq = []
                fourToken = [0, 0, 0, 0]
                with open('/home/jin/Documents/Generated Data/Grouped Chain/' + str(file), 'r') as f:
                    reader = csv.reader(f)
                    for (j, l) in enumerate(reader):
                        # remove the head
                        if (j == 0):
                            continue
                        else:
                            petriNet_T = attack[0][stepNum]  # copy that for each file
                            petriNet_P = attack[1][stepNum]
                            petriNet_A1 = attack[2][stepNum]
                            petriNet_A2 = attack[3][stepNum]
                            petriNet_L = attack[4][stepNum]
                            #print(petriNet_T)
                            l = {'Protocol': l[1],'Time': l[2]}
                            if l['Protocol'] in petriNet_T and (len(inputSeq) < 5*petriNet_L):
                                inputSeq.append([l['Protocol'], l['Time']])
                                fitness = protoListFlow(petriNet_T, petriNet_P, petriNet_A1, petriNet_A2, petriNet_L, fourToken, inputSeq)

                                if fitness > 0.8:
                                    if stepNum < len(attack[0])-1:
                                        chainNum = file.split('_')[3].split('.')[0]
                                        attackSeq.append([chainNum, fitness, i, stepNum, inputSeq])
                                        print([chainNum, fitness, i, stepNum, inputSeq])
                                        inputSeq = []
                                        stepNum = stepNum + 1
                                    else:
                                        print([chainNum, fitness, i, stepNum, inputSeq])
                                        print('Attack Finished')
                                        break
                                for place in petriNet_P:
                                    petriNet_P[place] = []
                                    fourToken = [0, 0, 0, 0]
        if len(attackSeq) > 0:
            name = ['Chain Number', 'Fitness', 'Attack Number', 'Step', 'Sequence']
            data = pd.DataFrame(columns=name, data=attackSeq)
            data.to_csv('/home/jin/Documents/Generated Data/Attack Sequence/sequence data.csv')
            print('Attack sequence finding done')
        else:
            print('no attack sequence found')
    return