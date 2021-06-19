from datastructure import windowTime
from datastructure import decayPeriod
from datastructure import endList

def fitCalculation(petriNetPlace):
    d = 0.00001
    n = 0
    for p in petriNetPlace:
        if petriNetPlace[p] != 0:
            n += 1
        d += 1
    return n/d

def simCal(srcIpRec, desIpRec, srcIpCur, desIpCur, IpFT, timeRec, timeCur, patternProb, knowledgeSim):
    SSDD = IpSimilarityCalculation(srcIpRec, srcIpCur, desIpRec, desIpCur)
    SDSD = IpSimilarityCalculation(srcIpRec, desIpCur, srcIpCur, desIpRec)
    ipSim = max(SSDD, SDSD)
    srcIpFreq = IpFT[srcIpCur]
    desIpFreq = IpFT[desIpCur]
    maxIpFreq = max(srcIpFreq, desIpFreq)
    IpInterval = float(timeCur) - float(timeRec)
    IpFTSim = IpFreqIntervalSim(IpInterval, decayPeriod, maxIpFreq)
    #sim = alpha * ipSim + ((1-alpha)/2) * IpFTSim + ((1-alpha)/2) * patternProb
    #sim = alpha * ipSim + (1 - alpha) * patternProb
    coeff = max(IpFTSim, patternProb)
    sim = coeff * (ipSim + knowledgeSim)
    #sim = IpFTSim * ipSim
    return sim

def fromAlertsrcProb(alertSrc, alertDes, alertList, patternMatrix):
    totalFreq = 0
    for a in alertList:
        totalFreq = totalFreq + patternMatrix[(a,alertDes)]
    if totalFreq !=0:
        return patternMatrix[(alertSrc,alertDes)]/totalFreq
    else:
        return 0

def windowUpdate(windowList, alertInfo, IpFT):
    time = alertInfo[0]
    srcip = alertInfo[2]
    desip = alertInfo[3]
    windowList.append(alertInfo)
    IpFreqIntervalIn(srcip, IpFT)
    IpFreqIntervalIn(desip, IpFT)
    while len(windowList) > 0:
        oldestInfo = windowList[0]
        oldest_time = oldestInfo[0]
        oldest_srcip = oldestInfo[2]
        oldest_desip = oldestInfo[3]
        if not validTimeGap(oldest_time, time, windowTime):
            windowList.pop(0)
            IpFreqIntervalOut(oldest_srcip, IpFT)
            IpFreqIntervalOut(oldest_desip, IpFT)
        else:
            break
    return

def patternMatrixInit(alertList, patternMatrix):
    for a1 in alertList:
        for a2 in alertList:
            patternMatrix[(a1, a2)] = 0
    #patternMatrix[('Mstream_Zombie','Stream_DoS')] = 100
    return

def petriNetFilter(petriNetPlace, resultList):
    l = len(resultList)
    templist = []
    for i in range(l):
        r = resultList[i]
        tran = r[1] + '-' + str(r[0])
        if petriNetPlace[tran] == 0:
            templist.append(resultList[i])
        elif r[1] in endList:
            templist.append(resultList[i])
        else:
            print(r)
    return templist

def IpFreqIntervalIn(Ip, IpFT):
    IpFT[Ip] = IpFT[Ip] + 1
    return IpFT[Ip]

def IpFreqIntervalOut(Ip, IpFT):
    IpFT[Ip] = IpFT[Ip] - 1
    return IpFT[Ip]

def produceToken(petriNetPlace, transition):
    petriNetPlace[transition] = 1
    return

def consumeToken(petriNetPlace, transition):
    #if petriNetPlace[transition] > 0:
    #    petriNetPlace[transition] = petriNetPlace[transition] - 1
    #else:
    petriNetPlace[transition] = 0
    return

def IpFreqIntervalSim(IpInterval, decayPeriod, IpFreq):
    ef = 1.05
    et = 1.05
    IpInterval = int(IpInterval)
    IpFreqSim = 1 - ef**(-int(IpFreq))
    IpIntervalSim = et**(-int(IpInterval/decayPeriod))
    return max(IpFreqSim, IpIntervalSim)

def patternFreqSim(patternFreq):
    ef = 1.05
    patternFreqSim = 1 - ef ** (-int(patternFreq))
    return patternFreqSim


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
    if max(sameNum1,sameNum2) == 32:
        return 1
    else:
        return max(sameNum1,sameNum2)/32

def validTimeGap(timeFormer, timeLatter, validGap):
    if float(timeLatter) - float(timeFormer) > validGap:
        return False
    else:
        return True

def timeConversion(Time):
    [h,m,s] = Time.split(':')
    t = 60*(float(m) + 60*float(h)) + float(s)
    return t

def timeConversionBack(t):
    t = int(t)
    h = t//(60*60)
    m = (t - 3600*h) // 60
    s = t - 3600*h - 60*m
    time = str(h) + ':' + str(m) + ':' + str(s)
    return time