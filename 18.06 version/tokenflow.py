from helperfunc import windowUpdate
from helperfunc import timeConversion
from helperfunc import patternMatrixInit
from helperfunc import fromAlertsrcProb
from helperfunc import simCal
from helperfunc import consumeToken
from helperfunc import produceToken
from helperfunc import fitCalculation
from helperfunc import petriNetFilter
from helperfunc import timeConversionBack
from helperfunc import IpSimilarityCalculation
from helperfunc import patternFreqSim
from datastructure import resultList
from datastructure import windowList
from datastructure import IpFT
from datastructure import alertList
from datastructure import patternMatrix
from datastructure import simT
from datastructure import fT
from datastructure import fileNumber
from datastructure import petriNetPlace
from datastructure import knowledgeMatrix
import csv
import pandas as pd
import numpy as np



def tokenReplay():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/tc_inside' + str(fileNumber) + '_alert.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                lastAlert = ''
                patternMatrixInit(alertList, patternMatrix)
                continue
            else:
                l = {'Time': timeConversion(l[0]),'SrcPort':l[1],'SrcIp':l[2],'DesPort':l[3],'DesIp':l[4],'AlertType':l[5]}
                preqList = []
                app = False
                windowUpdate(windowList, [l['Time'], l['AlertType'], l['SrcIp'], l['DesIp']],IpFT)
                correlationList = resultList[0:4] + windowList[0:-1]
                #correlationList = windowList
                for ai in correlationList:
                    aiTime = ai[0]
                    aiType = ai[1]
                    aiSrcIp = ai[2]
                    aiDesIp = ai[3]
                    #patternProb = patternFreqSim(patternMatrix[(aiType, l['AlertType'])])
                    patternProb = fromAlertsrcProb(aiType, l['AlertType'], alertList, patternMatrix)
                    sim = simCal(aiSrcIp, aiDesIp, l['SrcIp'], l['DesIp'], IpFT, aiTime, l['Time'], patternProb, knowledgeMatrix[(aiType, l['AlertType'])])
                    #patternMatrix[(aiType, l['AlertType'])] = patternMatrix[(aiType, l['AlertType'])] + sim
                    if sim >= simT:
                        patternMatrix[(aiType, l['AlertType'])] = patternMatrix[(aiType, l['AlertType'])] + 1
                        preqList.append(aiType + '-' + timeConversionBack(aiTime))
                        app = True
                        consumeToken(petriNetPlace, aiType + '-' + timeConversionBack(aiTime))
                if app:
                    resultList.append([l['Time'], l['AlertType'], l['SrcIp'], l['DesIp'], preqList])
                    produceToken(petriNetPlace, aiType + '-' + timeConversionBack(aiTime))
                #patternMatrix[(lastAlert, l['AlertType'])] = patternMatrix[(lastAlert, l['AlertType'])] + 1
                #lastAlert = l['AlertType']
                fitCal = fitCalculation(petriNetPlace)
                if fitCal > fT:
                    break

        for j in range(len(resultList)):
            resultList[j][0] = timeConversionBack(resultList[j][0])

        name = ['Time(after conversion)', 'AlertType', 'SrcIp', 'DesIp', 'prerequisiteList']
        data = pd.DataFrame(columns=name, data=resultList)
        data.to_csv('/home/jin/Documents/Generated Data/1806_record_withoutPetri' + str(fileNumber) + '.csv', index=False)

        result = petriNetFilter(petriNetPlace, resultList)
        name = ['Time(after conversion)', 'AlertType', 'SrcIp', 'DesIp', 'prerequisiteList']
        data = pd.DataFrame(columns=name, data=result)
        data.to_csv('/home/jin/Documents/Generated Data/1806_record' + str(fileNumber) + '.csv', index=False)
        print('Done')