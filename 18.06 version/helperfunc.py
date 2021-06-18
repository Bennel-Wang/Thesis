def patternMatrixInit(alertList, patternMatrix):
    for a1 in alertList:
        for a2 in alertList:
            patternMatrix[(a1, a2)] = 0
    return

def IpFreqIntervalIn(Ip, time, IpFT):
    f, _ = IpFT[Ip].split('-')
    f = int(f) + 1
    IpFT[Ip] = str(f) + '-' + str(time)
    return

def IpFreqIntervalOut(Ip, time, IpFT):
    f, _ = IpFT[Ip].split('-')
    f = int(f) - 1
    if f == 0:
        IpFT[Ip] = ''
    return

def produceToken(petriNetPlace, transition):
    petriNetPlace[transition] = petriNetPlace[transition] + 1
    return

def consumeToken(petriNetPlace, transition):
    if petriNetPlace[transition] > 0:
        petriNetPlace[transition] = petriNetPlace[transition] - 1
    else:
        petriNetPlace[transition] = 0
    return

def IpFreqIntervalSim(IpInterval, decayPeriod, IpFreq):
    e = 2.7183
    IpInterval = int(IpInterval)
    IpFreqSim = 1 - e**(-int(IpFreq))
    IpIntervalSim = e**(-int(IpInterval/decayPeriod))
    return max(IpFreqSim, IpIntervalSim)

def patternFreqSim(patternFreq):
    e = 2.7183
    patternFreqSim = 1 - e ** (-int(patternFreq))
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