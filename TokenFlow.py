import collections
import os
import csv
import pandas as pd
import numpy as np

#first initialize a maximum number, then if any new, update the number and re-normalize
indexMap = {'Start':0, 'Sadmind_Ping':1, 'TelnetTerminaltype': 2, 'Email_Almail_Overflow':3, 'Email_Ehlo':4, 'FTP_User':5, 'FTP_Pass':6,
            'FTP_Syst':7, 'HTTP_Java':8, 'HTTP_Shells':9, 'Admind':10, 'Sadmind_Amslverify_Overflow':11, 'Rsh':12, 'Mstream_Zombie':13,
            'HTTP_Cisco_Catalyst_Exec':14, 'SSH_Detected':15, 'Email_Debug':16, 'TelnetXdisplay':17, 'TelnetEnvAll':18, 'Stream_DoS':19,
            'FTP_Put':20, 'Email_Turn':21, 'HTTP_ActiveX':22,'Port_Scan':23, 'TCP_Urgent_Data':24,'RIPExpire':25,'RIPAdd':26}
alertList= ['Start', 'Sadmind_Ping', 'TelnetTerminaltype', 'Email_Almail_Overflow', 'Email_Ehlo', 'FTP_User', 'FTP_Pass',
            'FTP_Syst', 'HTTP_Java', 'HTTP_Shells', 'Admind', 'Sadmind_Amslverify_Overflow', 'Rsh', 'Mstream_Zombie',
            'HTTP_Cisco_Catalyst_Exec', 'SSH_Detected', 'Email_Debug', 'TelnetXdisplay', 'TelnetEnvAll', 'Stream_DoS',
            'FTP_Put', 'Email_Turn', 'HTTP_ActiveX','Port_Scan', 'TCP_Urgent_Data','RIPExpire','RIPAdd']


def updateProbabiity(similarity, lastTransition, currentTransition, ProbabilityMatrix, indexMap):
    coefficient = 0.5
    lastProbability = ProbabilityMatrix[indexMap[lastTransition], indexMap[currentTransition]]
    #print(coefficient, ProbabilityMatrix[indexMap[lastTransition], indexMap[currentTransition]],indexMap[currentTransition],similarity)
    ProbabilityMatrix[indexMap[lastTransition], indexMap[currentTransition]] = coefficient * ProbabilityMatrix[
        indexMap[lastTransition], indexMap[currentTransition]] + (1 - coefficient) * similarity
    alpha = ProbabilityMatrix[indexMap[lastTransition], indexMap[currentTransition]]/lastProbability
    #print(alpha,lastProbability)
    beta = (1-alpha)/(1-lastProbability) + alpha
    ProbabilityMatrix[:, indexMap[currentTransition]] = ProbabilityMatrix[:, indexMap[currentTransition]] * beta
    ProbabilityMatrix[indexMap[lastTransition], indexMap[currentTransition]] = ProbabilityMatrix[indexMap[lastTransition], indexMap[currentTransition]]/beta



def initializeNet(net_P, indexMap):
    for alert in indexMap:
        net_P[alert] = 0#(len(indexMap)-1)/2

def initializeProbabiity(ProbabilityMatrix, indexMap):
    for i in range(len(indexMap)):
        for j in range(len(indexMap)):
            ProbabilityMatrix[i, j] = 1/len(indexMap)
            #print(ProbabilityMatrix[i, j])

#In: 4 tokens list, log number
#Out: improved fitness value
#Function: calculate fitness
def calFitness(fourToken, factor = (len(indexMap)-1)/2):
    const = 0.00001
    p = fourToken[0]     #produced
    c = fourToken[1]     #consumed
    m = fourToken[2]     #missed
    r = fourToken[3]     #remained
    fitness = 1 / 2 * (1 - m / (c + const)) + 1 / 2 * (1 - r / (p + const))
    #if r - factor > 0:
    #    fitness =  1/2 * (1 - m/(c+const)) + 1/2 * (1 - (r-factor)/(p+const))    #for numerator and denominator all 0, fitness = 0
    #else:
    #    fitness =  1/2 * (1 - m/(c+const))
    return fitness


#In:petri net, node, current time,  four token list, token consume deadline, place weighting factor
#Out:/revised net
#Function:consume/miss w token flow
def consumeToken(net_P, node, fourToken, w):
    # silent activity
    if net_P[node] - w >= 0:
        net_P[node] = net_P[node] - w
        fourToken[1] = fourToken[1] + w             # consume w token
    else:
        net_P[node] = 0
        missingToken = w - net_P[node]
        fourToken[2] = fourToken[2] + missingToken  # miss w token
        fourToken[1] = fourToken[1] + w             # consume w token
    return

# In:petri net, node, current time, four token list, token produce delay, place weighting factor
# Out:/revised net
# Function:produce/remain one token flow, end not remain
def produceToken(net_P, node, fourToken, w = 1):
    net_P[node] = net_P[node] + w     #append the produced time
    fourToken[0] = fourToken[0] + w
    fourToken[3] = fourToken[0] - fourToken[1] + fourToken[2]
    return


def IpSimilarityCalculation(Ip11, Ip12, Ip21, Ip22):
    sameNum1 = 0
    sameNum2 = 0
    [firstBit11, secondBit11, ThirdBit11, FourthBit11] = Ip11.split('.')
    IpBin11= bin(int(firstBit11))[2:]+ bin(int(secondBit11))[2:]+bin(int(ThirdBit11))[2:]+ bin(int(FourthBit11))[2:]
    [firstBit12, secondBit12, ThirdBit12, FourthBit12] = Ip12.split('.')
    IpBin12 = bin(int(firstBit12))[2:] + bin(int(secondBit12))[2:] + bin(int(ThirdBit12))[2:] + bin(int(FourthBit12))[2:]
    [firstBit21, secondBit21, ThirdBit21, FourthBit21] = Ip21.split('.')
    IpBin21 = bin(int(firstBit21))[2:] + bin(int(secondBit21))[2:] + bin(int(ThirdBit21))[2:] + bin(int(FourthBit21))[2:]
    [firstBit22, secondBit22, ThirdBit22, FourthBit22] = Ip22.split('.')
    IpBin22 = bin(int(firstBit22))[2:] + bin(int(secondBit22))[2:] + bin(int(ThirdBit22))[2:] + bin(int(FourthBit22))[2:]
    for i in range(32):
        if IpBin11[i] == IpBin21[i]:
            sameNum1 = sameNum1 + 1
        else:
            break
    for j in range(32):
        if IpBin12[j] == IpBin22[j]:
            sameNum2 = sameNum2 + 1
        else:
            break
    #print(IpBin11,IpBin12,IpBin21,IpBin22)
    return max(sameNum1,sameNum2)/32


def portSimilarityCalculation(Port11, Port12, Port21, Port22):
    if ((Port11 == Port21) and (Port12 == Port22)):
        return 1
    elif ((Port11 == Port22) and (Port12 == Port21)):
        return 1
    else:
        return 0

def timeSimilarityCalculation(currTime,lastTime):
    currTime = timeConversion(currTime)
    lastTime = timeConversion(lastTime)
    gap = float(currTime) - float(lastTime)
    e = 2.718
    print(e**(-gap))
    return e**(-gap)

def timeConversion(Time):
    [h,m,s] = Time.split(':')
    t = 60*(float(m) + 60*float(h)) + float(s)
    return t

def similarityCal(lastSrcIp, currSrcIp, lastDesIp, currDesIp, lastSrcPort, lastDesPort, currSrcPort, currDesPort, lastTime, currTime):
    coefficientIp = 0.6
    coefficientTime = 0.25
    coefficientPort = 0.15
    if lastSrcIp == 'xxx.xxx.xxx.xxx':
        similarity = 0.5
    else:
        SSDDIpSimilarity = IpSimilarityCalculation(lastSrcIp, currSrcIp, lastDesIp, currDesIp)
        SDSDIpSimilarity = IpSimilarityCalculation(lastSrcIp, currDesIp, lastDesIp, currSrcIp)
        IpSimilarity = coefficientIp * max(SSDDIpSimilarity,SDSDIpSimilarity)
        portSimilarity = coefficientPort * portSimilarityCalculation(lastSrcPort, lastDesPort, currSrcPort, currDesPort)
        timeSimilarity = coefficientTime * timeSimilarityCalculation(currTime,lastTime)
        #print(currTime,lastTime, timeSimilarity)
        similarity = IpSimilarity + portSimilarity + timeSimilarity
    return similarity

# In: petriNet_T, petriNet_P, petriNet_A1, petriNet_A2, fourToken, protocol, time
# Out: \
# Function: fire a protocol
def fireAlert(fourToken, lastSrcIp, currSrcIp, lastDesIp, currDesIp, lastSrcPort, currSrcPort, lastDesPort, currDesPort, lastTime, currTime, lastAlert, currentAlert, petriNet_P, ProbabilityMatrix, indexMap):
    s = similarityCal(lastSrcIp, currSrcIp, lastDesIp, currDesIp, lastSrcPort, lastDesPort, currSrcPort, currDesPort, lastTime, currTime)
    updateProbabiity(s, lastAlert, currentAlert, ProbabilityMatrix,indexMap)
    for t in indexMap:
        consumeToken(petriNet_P, t, fourToken, ProbabilityMatrix[indexMap[lastAlert], indexMap[currentAlert]])
    produceToken(petriNet_P, currentAlert, fourToken, 1)
    fitness = calFitness(fourToken)
    return fitness


#In:\grouped chain file data
#Out: Attack chain
#Function: Doing token replay, output attack chain
def tokenReplay():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside2_alert.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                net_P = collections.defaultdict(float)
                ProbabilityMatrix = np.zeros((len(indexMap),len(indexMap)),dtype=float) #arange(len(indexMap)**2).reshape(len(indexMap),len(indexMap))
                initializeNet(net_P, indexMap)
                initializeProbabiity(ProbabilityMatrix, indexMap)
                lastSrcIp = 'xxx.xxx.xxx.xxx'
                lastDesIp =  'xxx.xxx.xxx.xxx'
                lastSrcPort = 'xx'
                lastDesPort = 'xx'
                lastTime = 'x:x:x'
                lastAlert = 'Start'
                fitnessT = 0.32
                pathT = 0.25
                fourToken = [0,0,0,0]
                path = []
                resList = []
                pathNum = 0
                continue
            else:
                l = {'Time': l[0],'SrcPort':l[1],'SrcIp':l[2],'DesPort':l[3],'DesIp':l[4],'AlertType':l[5]}
                initializeProbabiity(ProbabilityMatrix, indexMap)
                fitness = fireAlert(fourToken, lastSrcIp, l['SrcIp'], lastDesIp, l['DesIp'], lastSrcPort, l['SrcPort'], lastDesPort, l['DesPort'], lastTime, l['Time'], lastAlert,l['AlertType'], net_P, ProbabilityMatrix, indexMap)
                if ProbabilityMatrix[indexMap[lastAlert],indexMap[l['AlertType']]] > pathT and ([lastAlert, l['AlertType'],l['SrcIp'],l['DesIp']] not in path):
                    resList.append([lastAlert, l['AlertType'], fitness,l['SrcIp'],l['DesIp'], ProbabilityMatrix[indexMap[lastAlert],indexMap[l['AlertType']]]])
                    path.append([lastAlert, l['AlertType'],l['SrcIp'],l['DesIp']])
                lastSrcIp = l['SrcIp']
                lastDesIp = l['DesIp']
                lastSrcPort = l['SrcPort']
                lastDesPort = l['DesPort']
                lastTime = l['Time']
                lastAlert = l['AlertType']
            if fitness > fitnessT:
                name = ['lastAlert', 'currAlert', 'fitness', 'SrcIp','DesIp', 'probability']
                data = pd.DataFrame(columns=name, data=resList)
                data.to_csv('/home/jin/Documents/Generated Data/record2.csv')
                break


                #print(fitness)
'''                if fitness > fitnessT:  #and len(resList) > 20:                           #step transition
                    for i in range(len(indexMap)):
                        for j in range(len(indexMap)):
                            p = ProbabilityMatrix[i, j]
                            if p > pathT: #and ([alertList[i], alertList[j]] not in path):
                                resList.append([alertList[i]+'->'+alertList[j], l['SrcIp'] +'->' + l['DesIp'], p])
                                path.append([alertList[i], alertList[j]])
                    #if 1:#len(resList) > 20:
                    #    print(fitness)
                    fourToken = [0, 0, 0, 0]
                    for p in net_P:
                        net_P[p] = 0
                    initializeNet(net_P, indexMap)
                    initializeProbabiity(ProbabilityMatrix, indexMap)
                    lastSrcIp = 'xxx.xxx.xxx.xxx'
                    lastDesIp = 'xxx.xxx.xxx.xxx'
                    lastSrcPort = 'xx'
                    lastDesPort = 'xx'
                    lastTime = 'x:x:x'
                    lastAlert = 'Start'
                    pathNum = pathNum +1
                    name = ['path','Ip', 'probability']
                    data = pd.DataFrame(columns=name, data=resList)
                    path = []
                    resList = []
                    data.to_csv('/home/jin/Documents/Generated Data/path_' + str(pathNum) +'.csv')
                    print('Attack sequence found')'''
                    #continue
    #return