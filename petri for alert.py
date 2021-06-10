import csv
import pandas as pd
from helperFunc import timeConversion
from helperFunc import validTimeGap
from helperFunc import IpSimilarityCalculation
from helperFunc import timeSimilarityCalculation
from helperFunc import freqSimilarityCalculation
from helperFunc import alertIpSim
from helperFunc import indexMap
from collections import defaultdict

datasetNum = 1
ipT = 0.75
corT = ipT + 1/2
winTime = 20*60             #maximum interval between steps
decayPeriod = winTime/10
hisAlertList = []
baseT = 2
baseF = 1.414
freqMatrix = [[0 for i in range(len(indexMap)+1)] for j in range(len(indexMap)+1)]
freqMatrix[13][19] = 3

def tokenReplay():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside' + str(datasetNum) + '_alert.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                tempRes = []
                res = []
                placeState = defaultdict()  #0for not alert, 1 for have token, -1 for no token
                continue
            else:
                l = {'Time': l[0],'SrcPort':l[1],'SrcIp':l[2],'DesPort':l[3],'DesIp':l[4],'AlertType':l[5]}
                l['Time'] = str(timeConversion(l['Time']))
                data = str(l['Time']) + '-' + l['AlertType'] + '-' + l['SrcIp'] + '-' + l['DesIp']
                while (len(hisAlertList)!=0):
                    r = hisAlertList[0]
                    rt = r.split('-')[0]
                    if not validTimeGap(rt, l['Time'], winTime):
                        hisAlertList.pop(0)
                    else:
                        break
                simAlert = []
                corAlert = []
                app = False
                for d in hisAlertList:
                    [time1, alertType1, ip1s, ip1d] = d.split('-')
                    ipSim = alertIpSim(ip1s, l['SrcIp'], ip1d, l['DesIp'])
                    timeSim = 0#timeSimilarityCalculation(time1, l['Time'], baseT,decayPeriod)
                    if ipSim > ipT:
                        simAlert.append(d)
                        freqMatrix[indexMap[alertType1]][indexMap[l['AlertType']]] = freqMatrix[indexMap[alertType1]][indexMap[l['AlertType']]]  + 1
                    cor = ipSim + timeSim + freqSimilarityCalculation(freqMatrix[indexMap[alertType1]][indexMap[l['AlertType']]],baseF)
                    if cor > corT:
                        corAlert.append(d)
                        app = True
                hisAlertList.append(data)
                if app or len(hisAlertList) == 0:
                    tempRes.append([corAlert, data])
                    placeState[data] = 1
                    for a in corAlert:
                        placeState[a] = -1
                    if data.split('-')[1] == 'Stream_DoS':
                        placeState[data] = -1
        for temp in tempRes:
            state = placeState[temp[1]]
            if state == -1:
                res.append(temp)
        name = ['correlationInfo', 'alertInfo']
        write = pd.DataFrame(columns=name, data=res)
        write.to_csv('/home/jin/Documents/Generated Data/petriAlertMethod' + str(datasetNum) + '-dataset.csv')
        print('End Detection ')

def main():
    tokenReplay()
if __name__ == '__main__':
    main()
