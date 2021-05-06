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

alertColorList= {'Start':-1, 'Sadmind_Ping':-1, 'TelnetTerminaltype':-1, 'Email_Almail_Overflow':-1, 'Email_Ehlo':-1, 'FTP_User':-1, 'FTP_Pass':-1,
            'FTP_Syst':-1, 'HTTP_Java':-1, 'HTTP_Shells':-1, 'Admind':-1, 'Sadmind_Amslverify_Overflow':-1, 'Rsh':-1, 'Mstream_Zombie':-1,
            'HTTP_Cisco_Catalyst_Exec':-1, 'SSH_Detected':-1, 'Email_Debug':-1, 'TelnetXdisplay':-1, 'TelnetEnvAll':-1, 'Stream_DoS':-1,
            'FTP_Put':-1, 'Email_Turn':-1, 'HTTP_ActiveX':-1,'Port_Scan':-1, 'TCP_Urgent_Data':-1,'RIPExpire':-1,'RIPAdd':-1}
#-1:not token, 0: consequence consumed, other number: token number


def calFitness(petriNet):
    totalTokenNum = 0
    emptyNum = 0
    for a in petriNet:
        tokenNum = petriNet[a]
        if tokenNum >0:  #not visited
            totalTokenNum = totalTokenNum + tokenNum
        if tokenNum == 0:   #successfully consumed
            emptyNum = emptyNum + 1
            totalTokenNum = totalTokenNum + 1
    fitness = emptyNum/totalTokenNum
    return fitness

def initializeNet(net_P, indexMap):
    for alert in indexMap:
        net_P[alert] = 0

def initializeCorrelation(CorrelationMatrix, indexMap):
    for i in range(len(indexMap)):
        for j in range(len(indexMap)):
            CorrelationMatrix[i, j] = 0

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

def similarityCal(SrcIp, currSrcIp, DesIp, currDesIp, Time, currTime):
    coefficientIp = 0.9
    coefficientTime = 0.1
    #coefficientPort = 0
    if SrcIp == 'xxx.xxx.xxx.xxx':
        similarity = 1
    else:
        SSDDIpSimilarity = IpSimilarityCalculation(SrcIp, currSrcIp, DesIp, currDesIp)
        SDSDIpSimilarity = IpSimilarityCalculation(SrcIp, currDesIp, DesIp, currSrcIp)
        IpSimilarity = coefficientIp * max(SSDDIpSimilarity, SDSDIpSimilarity)
        #portSimilarity = coefficientPort * portSimilarityCalculation(lastSrcPort, lastDesPort, currSrcPort, currDesPort)
        timeSimilarity = coefficientTime * timeSimilarityCalculation(currTime,Time)
        #print(currTime,lastTime, timeSimilarity)
        similarity = IpSimilarity + timeSimilarity
    return similarity

#In:petri net, node, current time,  four token list, token consume deadline, place weighting factor
#Out:/revised net
#Function:consume/miss w token flow
def consumeToken(net_P, node, w=1):
    # silent activity
    if net_P[node] - w >= 0:    #have token to consume
        net_P[node] = net_P[node] - w
        return True
    elif net_P[node] == 0:
        return True
    else:       #not visited
        return False

# In:petri net, node, current time, four token list, token produce delay, place weighting factor
# Out:/revised net
# Function:produce/remain one token flow, end not remain
def produceToken(net_P, node, w = 1):
    net_P[node] = net_P[node] + w     #append the produced time
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



def updateCorrelation(similarity, Transition, currentTransition, correlationMatrix, indexMap):
    coefficient = 0.3
    correlationMatrix[indexMap[Transition], indexMap[currentTransition]] = coefficient * correlationMatrix[
        indexMap[Transition], indexMap[currentTransition]] + (1 - coefficient) * similarity



# In: petriNet_T, petriNet_P, petriNet_A1, petriNet_A2, fourToken, protocol, time
# Out: \
# Function: fire a protocol
def fireAlert(currSrcIp, currDesIp, currentAlert, currentTime, petriNet_P, correlationMatrix, indexMap, alertIpList):
    consumeList = []
    for alert in alertIpList:
        s = 0
        IpNum = 0
        for Ip in alertIpList[alert]:
            SrcIp, DesIp, time = Ip.split('-')
            s = s + similarityCal(SrcIp, currSrcIp, DesIp, currDesIp,time, currentTime)
            IpNum = IpNum + 1
        updateCorrelation(s/(IpNum+0.0001), alert, currentAlert, correlationMatrix, indexMap)

    for t in indexMap:
        if correlationMatrix[indexMap[t], indexMap[currentAlert]] >= 0.85:
            success = consumeToken(petriNet_P, t)
            if success:
                consumeList.append(t)
    produceToken(petriNet_P, currentAlert, 1)
    fitness = calFitness(petriNet_P)
    alertIpList[currentAlert].append(currSrcIp + '-' + currDesIp + '-' + currentTime)

    for a in alertIpList:
        while len(alertIpList[a])>0:
            if timeConversion(currentTime) - timeConversion(alertIpList[a][0].split('-')[2]) > 600:
                alertIpList[a].pop(0)
            else:
                break
    return [consumeList, fitness]

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
                net_P = alertColorList
                correlationMatrix = np.zeros((len(indexMap),len(indexMap)),dtype=float) #arange(len(indexMap)**2).reshape(len(indexMap),len(indexMap))
                initializeNet(net_P, indexMap)
                initializeCorrelation(correlationMatrix, indexMap)
                pathTl = 0.8      #prevent no frequent
                lastMiss = 0
                Mt = 0.2
                fourToken = [0,0,0,0]
                resList = []
                continue
            else:
                l = {'Time': l[0],'SrcPort':l[1],'SrcIp':l[2],'DesPort':l[3],'DesIp':l[4],'AlertType':l[5]}
                [consumeList, fitness] = fireAlert(l['SrcIp'], l['DesIp'],l['AlertType'], l['Time'],net_P, correlationMatrix, indexMap, alertIpList)
                if len(consumeList) > 0:
                    resList.append([l['Time'], consumeList, l['AlertType'],  fitness,l['SrcIp'],l['DesIp']])

        #if fitness > fitnessT:
        name = ['Time', 'consumeAlert','currAlert', 'fitness', 'SrcIp','DesIp']
        data = pd.DataFrame(columns=name, data=resList)
        data.to_csv('/home/jin/Documents/Generated Data/record-new-color.csv')


def main():
    tokenReplay()
    #hyperAlertGrouping()
    print('Detection done')
if __name__ == '__main__':
    main()
