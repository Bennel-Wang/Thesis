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

alertIpList= {'Start':[], 'Sadmind_Ping':[], 'TelnetTerminaltype':[], 'Email_Almail_Overflow':[], 'Email_Ehlo':[], 'FTP_User':[], 'FTP_Pass':[],
            'FTP_Syst':[], 'HTTP_Java':[], 'HTTP_Shells':[], 'Admind':[], 'Sadmind_Amslverify_Overflow':[], 'Rsh':[], 'Mstream_Zombie':[],
            'HTTP_Cisco_Catalyst_Exec':[], 'SSH_Detected':[], 'Email_Debug':[], 'TelnetXdisplay':[], 'TelnetEnvAll':[], 'Stream_DoS':[],
            'FTP_Put':[], 'Email_Turn':[], 'HTTP_ActiveX':[],'Port_Scan':[], 'TCP_Urgent_Data':[],'RIPExpire':[],'RIPAdd':[]}

alertTokenList= {'Start':[0,0,0,0], 'Sadmind_Ping':[0,0,0,0], 'TelnetTerminaltype':[0,0,0,0], 'Email_Almail_Overflow':[0,0,0,0], 'Email_Ehlo':[0,0,0,0], 'FTP_User':[0,0,0,0], 'FTP_Pass':[0,0,0,0],
            'FTP_Syst':[0,0,0,0], 'HTTP_Java':[0,0,0,0], 'HTTP_Shells':[0,0,0,0], 'Admind':[0,0,0,0], 'Sadmind_Amslverify_Overflow':[0,0,0,0], 'Rsh':[0,0,0,0], 'Mstream_Zombie':[0,0,0,0],
            'HTTP_Cisco_Catalyst_Exec':[0,0,0,0], 'SSH_Detected':[0,0,0,0], 'Email_Debug':[0,0,0,0], 'TelnetXdisplay':[0,0,0,0], 'TelnetEnvAll':[0,0,0,0], 'Stream_DoS':[0,0,0,0],
            'FTP_Put':[0,0,0,0], 'Email_Turn':[0,0,0,0], 'HTTP_ActiveX':[0,0,0,0],'Port_Scan':[0,0,0,0], 'TCP_Urgent_Data':[0,0,0,0],'RIPExpire':[0,0,0,0],'RIPAdd':[0,0,0,0]}


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
def calFitness(fourToken):
    p = fourToken[0]     #produced
    c = fourToken[1]     #consumed
    m = fourToken[2]     #missed
    r = fourToken[3]     #remained
    if c!=0 and p!=0:
        fitness = 1 / 2 * (1 - m / c) + 1 / 2 * (1 - r / p)
    else:
        fitness = 0
    print(fourToken)
    return fitness


def portSimilarityCalculation(Port11, Port12, Port21, Port22):
    if ((Port11 == Port21) and (Port12 == Port22)):
        return 1
    elif ((Port11 == Port22) and (Port12 == Port21)):
        return 1
    elif ((Port11 == Port21) or (Port12 == Port22)):
        return 1
    elif ((Port11 == Port22) or (Port12 == Port21)):
        return 1
    else:
        return 0

def timeSimilarityCalculation(currTime,lastTime):
    currTime = timeConversion(currTime)
    lastTime = timeConversion(lastTime)
    gap = float(currTime) - float(lastTime)
    e = 2.718
    #print('time', e**(-0.01*gap))
    return float(e**(-0.01*gap))

def timeConversion(Time):
    [h,m,s] = Time.split(':')
    t = 60*(float(m) + 60*float(h)) + float(s)
    return t

def similarityCal(lastSrcIp, currSrcIp, lastDesIp, currDesIp, lastTime, currTime):
    coefficientIp = 0.8
    coefficientTime = 0.2
    #coefficientPort = 0
    if lastSrcIp == 'xxx.xxx.xxx.xxx':
        similarity = 0.5
    else:
        SSDDIpSimilarity = IpSimilarityCalculation(lastSrcIp, currSrcIp, lastDesIp, currDesIp)
        SDSDIpSimilarity = IpSimilarityCalculation(lastSrcIp, currDesIp, lastDesIp, currSrcIp)
        IpSimilarity = coefficientIp * max(SSDDIpSimilarity, SDSDIpSimilarity)
        #portSimilarity = coefficientPort * portSimilarityCalculation(lastSrcPort, lastDesPort, currSrcPort, currDesPort)
        timeSimilarity = coefficientTime * timeSimilarityCalculation(currTime,lastTime)
        #print(currTime,lastTime, timeSimilarity)
        similarity = IpSimilarity + timeSimilarity
    return similarity

#In:petri net, node, current time,  four token list, token consume deadline, place weighting factor
#Out:/revised net
#Function:consume/miss w token flow
def consumeToken(net_P, node, fourToken, w, alertTokenList):
    # silent activity
    if net_P[node] - w >= 0:
        net_P[node] = net_P[node] - w
        fourToken[1] = fourToken[1] + w             # consume w token
        alertTokenList[node][1] = alertTokenList[node][1] + w
    else:
        missingToken = w - net_P[node]
        net_P[node] = 0
        fourToken[2] = fourToken[2] + missingToken  # miss w token
        fourToken[1] = fourToken[1] + w             # consume w token
        alertTokenList[node][2] = alertTokenList[node][2] + missingToken
        alertTokenList[node][1] = alertTokenList[node][1] + w
    return

# In:petri net, node, current time, four token list, token produce delay, place weighting factor
# Out:/revised net
# Function:produce/remain one token flow, end not remain
def produceToken(net_P, node, fourToken, w = 1):
    net_P[node] = net_P[node] + w     #append the produced time
    fourToken[0] = fourToken[0] + w
    fourToken[3] = fourToken[0] - fourToken[1] + fourToken[2]
    return


def IpSimilarityCalculation(Ip11, Ip21, Ip12, Ip22):        #last source, current source, last destination, current destination
    sameNum1 = 0
    sameNum2 = 0
    [firstBit11, secondBit11, ThirdBit11, FourthBit11] = Ip11.split('.')
    IpBin11= bin(int(firstBit11))[2:].zfill(8)+ bin(int(secondBit11))[2:].zfill(8)+bin(int(ThirdBit11))[2:].zfill(8)+ bin(int(FourthBit11))[2:].zfill(8)
    [firstBit12, secondBit12, ThirdBit12, FourthBit12] = Ip12.split('.')
    IpBin12 = bin(int(firstBit12))[2:].zfill(8) + bin(int(secondBit12))[2:].zfill(8) + bin(int(ThirdBit12))[2:].zfill(8) + bin(int(FourthBit12))[2:].zfill(8)
    [firstBit21, secondBit21, ThirdBit21, FourthBit21] = Ip21.split('.')
    IpBin21 = bin(int(firstBit21))[2:].zfill(8) + bin(int(secondBit21))[2:].zfill(8) + bin(int(ThirdBit21))[2:].zfill(8) + bin(int(FourthBit21))[2:].zfill(8)
    [firstBit22, secondBit22, ThirdBit22, FourthBit22] = Ip22.split('.')
    IpBin22 = bin(int(firstBit22))[2:].zfill(8) + bin(int(secondBit22))[2:].zfill(8) + bin(int(ThirdBit22))[2:].zfill(8) + bin(int(FourthBit22))[2:].zfill(8)
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
    #print(Ip11, Ip21, Ip12, Ip22)
    #print(sameNum1, sameNum2)
    #return max(sameNum1,sameNum2)/32
    if max(sameNum1,sameNum2) == 32:
        return 1
    else:
        return max(sameNum1,sameNum2)/32



def updateProbabiity(similarity, Transition, currentTransition, ProbabilityMatrix, indexMap):
    coefficient = 0.2
    lastProbability = ProbabilityMatrix[indexMap[Transition], indexMap[currentTransition]] + 0.0000001 #prevent denominator to be 0
    #print(coefficient, ProbabilityMatrix[indexMap[lastTransition], indexMap[currentTransition]],indexMap[currentTransition],similarity)
    ProbabilityMatrix[indexMap[Transition], indexMap[currentTransition]] = coefficient * ProbabilityMatrix[
        indexMap[Transition], indexMap[currentTransition]] + (1 - coefficient) * similarity
    alpha = ProbabilityMatrix[indexMap[Transition], indexMap[currentTransition]]/lastProbability
    #print(alpha,lastProbability)
    beta = (1-alpha)/(1-lastProbability) + alpha + 0.0000001  #prevent denominator to be 0
    ProbabilityMatrix[:, indexMap[currentTransition]] = ProbabilityMatrix[:, indexMap[currentTransition]] * beta
    ProbabilityMatrix[indexMap[Transition], indexMap[currentTransition]] = ProbabilityMatrix[indexMap[Transition], indexMap[currentTransition]]/beta
    #print(sum(ProbabilityMatrix[:, indexMap[currentTransition]]))
    if beta < 1:
        return 'increase'
    else:
        return 'decrease'

def normalizeProbability(currentAlert, ProbabilityMatrix, indexMap):
    totalSimilarity = sum(ProbabilityMatrix[:, indexMap[currentAlert]])
    if totalSimilarity !=0:
        ProbabilityMatrix[:, indexMap[currentAlert]] = ProbabilityMatrix[:, indexMap[currentAlert]]/totalSimilarity

# In: petriNet_T, petriNet_P, petriNet_A1, petriNet_A2, fourToken, protocol, time
# Out: \
# Function: fire a protocol
def fireAlert(fourToken, currSrcIp, currDesIp, currentAlert, currentTime, petriNet_P, ProbabilityMatrix, indexMap, alertIpList):
    maxAlert = 'Start'
    maxSimilarity = 0
    for alert in alertIpList:
        #if alert != currentAlert:
        s = 0
        IpNum = 0
        for Ip in alertIpList[alert]:
            SrcIp, DesIp, time = Ip.split('-')
            s = s + similarityCal(SrcIp, currSrcIp, DesIp, currDesIp,time, currentTime)
            IpNum = IpNum + 1
        if IpNum != 0:
            if s/IpNum >= maxSimilarity:
                maxSimilarity = s/IpNum
                maxAlert = alert
    updateProbabiity(maxSimilarity, maxAlert, currentAlert, ProbabilityMatrix, indexMap)
    for t in indexMap:
        consumeToken(petriNet_P, t, fourToken, ProbabilityMatrix[indexMap[t], indexMap[currentAlert]],alertTokenList)
    produceToken(petriNet_P, currentAlert, fourToken, 1)
    fitness = calFitness(fourToken)
    alertIpList[currentAlert].append(currSrcIp + '-' + currDesIp + '-' + currentTime)
    #if len(alertIpList[currentAlert]) > 1:
    for a in alertIpList:
        while len(alertIpList[a])>0:
            if timeConversion(currentTime) - timeConversion(alertIpList[a][0].split('-')[2]) > 300:
                alertIpList[a].pop(0)
            else:
                break
    print(maxAlert)
    return [maxAlert, fitness]

def hyperAlertGrouping():
    with open('/home/jin/Documents/Generated Data/record-new1.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                result = []
                continue
            else:
                l = {'Time': l[1], 'lastAlert': l[2], 'currAlert': l[3], 'fitness': l[4], 'SrcIp': l[5], 'DesIp': l[6], 'probability':l[7], 'remain-lastRemain':l[8]}
                #print(l)
                for i in range(0,len(result)):
                    #gap = timeConversion(l['Time']) - timeConversion(result[i][0])
                    if((l['lastAlert'] == result[i][1]) and (l['currAlert'] == result[i][2])):
                        if (l['SrcIp'] == result[i][4]) and (l['DesIp'] in result[i][5]):
                            #print(gap)
                            break   #group
                        elif (l['SrcIp'] == result[i][4]):
                            result[i][5].append(l['DesIp'])
                            break
                        #elif (l['DesIp'] in result[i][5]):
                        #    result[i][4].append(l['SrcIp'])
                        #    break   #group
                else:   #all with not satisfy
                    result.append([l['Time'], l['lastAlert'], l['currAlert'], l['fitness'], l['SrcIp'], [l['DesIp']]])
                #record.append(
                #    {'Time': l['Time'], 'lastAlert': l['lastAlert'], 'currAlert': l['currAlert'], 'SrcIp': l['SrcIp'],
                #     'DesIp': l['DesIp']})
        name = ['Time', 'lastAlert', 'currAlert', 'fitness', 'SrcIp', 'DesIp']
        data = pd.DataFrame(columns=name, data=result)
        data.to_csv('/home/jin/Documents/Generated Data/recordnew1-hyper.csv')
            # break



#In:\grouped chain file data
#Out: Attack chain
#Function: Doing token replay, output attack chain
def tokenReplay():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside1_alert.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                net_P = collections.defaultdict(float)
                ProbabilityMatrix = np.zeros((len(indexMap),len(indexMap)),dtype=float) #arange(len(indexMap)**2).reshape(len(indexMap),len(indexMap))
                initializeNet(net_P, indexMap)
                initializeProbabiity(ProbabilityMatrix, indexMap)
                pathTl = 0.8      #prevent no frequent
                lastMiss = 0
                Mt = 0.2
                fourToken = [0,0,0,0]
                resList = []
                continue
            else:
                l = {'Time': l[0],'SrcPort':l[1],'SrcIp':l[2],'DesPort':l[3],'DesIp':l[4],'AlertType':l[5]}
                [maxAlert, fitness] = fireAlert(fourToken, l['SrcIp'], l['DesIp'],l['AlertType'], l['Time'],net_P, ProbabilityMatrix, indexMap, alertIpList)

                if ProbabilityMatrix[indexMap[maxAlert],indexMap[l['AlertType']]] > pathTl and (fourToken[2] - lastMiss < Mt):
                    resList.append([l['Time'], maxAlert, l['AlertType'],  fitness,l['SrcIp'],l['DesIp'], ProbabilityMatrix[indexMap[maxAlert],indexMap[l['AlertType']]],fourToken[2]- lastMiss])
                lastMiss = fourToken[2]
        #if fitness > fitnessT:
        name = ['Time', 'Alert','currAlert', 'fitness', 'SrcIp','DesIp','Probability','miss- lastMiss']
        data = pd.DataFrame(columns=name, data=resList)
        data.to_csv('/home/jin/Documents/Generated Data/record-new1.csv')

        datalist = []
        for n in alertTokenList:
            datalist.append([n, alertTokenList[n]])
        nameList = ['Alert', 'p-c-m-r']
        data = pd.DataFrame(columns=nameList, data=datalist)
        data.to_csv('/home/jin/Documents/Generated Data/Token1.csv')

def main():
    tokenReplay()
    hyperAlertGrouping()
    print('Detection done')
if __name__ == '__main__':
    main()
