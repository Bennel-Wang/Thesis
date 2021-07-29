#helper function definition
from para import expBase
from para import stepWinT

#take the time from alert information and convert into int
def takeTime(rec):
    return int(timeConversion(rec[0]))

#xx:xx:xx to xx second
def timeConversion(Time):
    [h,m,s] = Time.split(':')
    t = 60*(float(m) + 60*float(h)) + float(s)
    return t

#time gap smaller than threshold, return true
def validTimeGap(timeFormer, timeLatter, validGap):
    if float(timeLatter) - float(timeFormer) > validGap:
        return False
    else:
        return True

#xx second to xx:xx:xx
def timeConversionBack(t):
    t = int(t)
    h = t//(60*60)
    m = (t - 3600*h) // 60
    s = t - 3600*h - 60*m
    time = str(h) + ':' + str(m) + ':' + str(s)
    return time

# correlation calculation
def correlationEstimation(timeInt, prop, base=expBase):
    # some order may upside down if we use probability rather than frequency
    # can not correlate the last alert and the first alert of two steps
    timeCor = base**(int(timeInt))
    return 0.5*timeCor + 0.5*prop        #when a step begin, cor is small, as time goes by, it becomes larger, its fluctuation and duration is useful

#slide the time window, uodate the frequency for condition propability calculation
def windowUpdate(windowList, alertInfo, alertFreq, patternFreq):
    alertTime, alertType, seqNum = alertInfo.split('-')
    if len(windowList) > 0:
        patternFreq[(windowList[len(windowList)-1].split('-')[1], alertType)] = patternFreq[(windowList[len(windowList)-1].split('-')[1], alertType)] + 1
    windowList.append(alertInfo)
    alertFreq[alertType] = alertFreq[alertType] + 1
    while len(windowList) > 0:
        oldestAlertInfo = windowList[0]
        oldestAlertTime, oldestAlertType,seqNum = oldestAlertInfo.split('-')
        if not validTimeGap(timeConversion(oldestAlertTime), timeConversion(alertTime), stepWinT):
            alertFreq[oldestAlertType] = alertFreq[oldestAlertType] - 1
            if len(windowList) > 1:
                patternFreq[(windowList[0].split('-')[1], windowList[1].split('-')[1])] = patternFreq[(windowList[0].split('-')[1], windowList[1].split('-')[1])] - 1
            windowList.pop(0)
        else:
            break
    return