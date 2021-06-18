from helperfunc import windowUpdate
from helperfunc import timeConversion
from helperfunc import patternMatrixInit
from helperfunc import fromAlertsrcProb
from helperfunc import simCal
from helperfunc import consumeToken
from helperfunc import produceToken
from helperfunc import fitCalculation
from helperfunc import petriNetFilter
from datastructure import resultList
from datastructure import windowList
from datastructure import IpFT
from datastructure import alertList
from datastructure import patternMatrix
from datastructure import simT
from datastructure import fT
from datastructure import petriNetPlace
import csv
import pandas as pd
import numpy as np



def tokenReplay():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside1_alert.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                patternMatrixInit(alertList, patternMatrix)
                continue
            else:
                l = {'Time': timeConversion(l[0]),'SrcPort':l[1],'SrcIp':l[2],'DesPort':l[3],'DesIp':l[4],'AlertType':l[5]}
                preqList = []
                app = False
                windowUpdate(windowList, [l['Time'], l['AlertType'], l['SrcIp'], l['DesIp']],IpFT)
                correlationList = resultList[0:4] + windowList
                for ai in correlationList:
                    aiTime = ai[0]
                    aiType = ai[1]
                    aiSrcIp = ai[2]
                    aiDesIp = ai[3]
                    patternProb = fromAlertsrcProb(aiType, l['AlertType'], alertList, patternMatrix)
                    sim = simCal(aiSrcIp, aiDesIp, l['SrcIp'], l['DesIp'], IpFT, aiTime, l['Time'], patternProb)
                    if sim >= simT:
                        patternMatrix[(aiType, l['AlertType'])] = patternMatrix[(aiType, l['AlertType'])] + 1
                        preqList.append(aiType + '-' + str(aiTime))
                        app = True
                        consumeToken(petriNetPlace, aiType + '-' + str(aiTime))
                if app:
                    resultList.append([l['Time'], l['AlertType'], l['SrcIp'], l['DesIp'], preqList])
                    produceToken(petriNetPlace, aiType + '-' + str(aiTime))
                    print([l['Time'], l['AlertType'], l['SrcIp'], l['DesIp'], preqList])
                fitCal = fitCalculation(petriNetPlace)
                if fitCal > fT:
                    break
        #petriNetFilter(petriNetPlace, resultList)
        name = ['Time', 'AlertType', 'SrcIp', 'DesIp', 'prerequisiteList']
        data = pd.DataFrame(columns=name, data=resultList)
        data.to_csv('/home/jin/Documents/Generated Data/1806_record1.csv')
        print('Done')