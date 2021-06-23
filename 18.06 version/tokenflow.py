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
from helperfunc import IpFreqIntervalIn
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
from datastructure import deinitialization
from datastructure import endList
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
                deinitialization()
                patternMatrixInit(alertList, patternMatrix)
                continue
            else:
                l = {'Time': timeConversion(l[0]),'SrcPort':l[1],'SrcIp':l[2],'DesPort':l[3],'DesIp':l[4],'AlertType':l[5]}
                preqList = []
                app = False
                windowUpdate(windowList, [l['Time'], l['AlertType'], l['SrcIp'], l['DesIp'],str(j)],IpFT)
                correlationList = resultList[0:5] + windowList[0:-1]
                for ai in correlationList:
                    aiTime = ai[0]
                    aiType = ai[1]
                    aiSrcIp = ai[2]
                    aiDesIp = ai[3]
                    ainum = ai[4]
                    patternProb = fromAlertsrcProb(aiType, l['AlertType'], alertList, patternMatrix)
                    sim = simCal(aiSrcIp, aiDesIp, l['SrcIp'], l['DesIp'], IpFT, aiTime, l['Time'], patternProb, knowledgeMatrix[(aiType, l['AlertType'])])
                    if sim >= simT:
                        patternMatrix[(aiType, l['AlertType'])] = patternMatrix[(aiType, l['AlertType'])] = \
                        patternMatrix[(aiType, l['AlertType'])] = patternMatrix[(aiType, l['AlertType'])] + 1
                        preqList.append(str(ainum) + '-' + aiType + '-' + timeConversionBack(aiTime))
                        app = True
                        consumeToken(petriNetPlace, aiType+'-'+str(ainum))
                        #print('c',aiType+'-'+str(ainum))

                        #for r in resultList:
                        #    if (str(ainum) == r[4] and aiType == r[1]):
                        #       break
                        #else:
                        #    resultList.append([aiTime, aiType, aiSrcIp, aiDesIp, str(ainum),['0-'+'Start'+'-0:0:0']])
                if app:
                    #IpFreqIntervalIn(l['SrcIp'], IpFT)
                    #IpFreqIntervalIn(l['DesIp'], IpFT)
                    resultList.append([l['Time'], l['AlertType'], l['SrcIp'], l['DesIp'], str(j), preqList])
                    produceToken(petriNetPlace, l['AlertType']+'-'+str(j))
                    #print('p',l['AlertType']+'-'+str(j))
                    patternMatrix[(lastAlert, l['AlertType'])] = patternMatrix[(lastAlert, l['AlertType'])] + 1
                    lastAlert = l['AlertType']
                fitCal = fitCalculation(petriNetPlace)
                if fitCal > fT:
                    break
                if l['AlertType'] in endList:
                    break
        for j in range(len(resultList)):
            resultList[j][0] = timeConversionBack(resultList[j][0])

        name = ['Time(after conversion)', 'AlertType', 'SrcIp', 'DesIp', 'Num','prerequisiteList']
        data = pd.DataFrame(columns=name, data=resultList)
        data.to_csv('/home/jin/Documents/Generated Data/1806_record_withoutPetri' + str(fileNumber) + '.csv', index=False)

        result = petriNetFilter(petriNetPlace, resultList)
        name = ['Time(after conversion)', 'AlertType', 'SrcIp', 'DesIp', 'Num','prerequisiteList']
        data = pd.DataFrame(columns=name, data=result)
        data.to_csv('/home/jin/Documents/Generated Data/1806_record' + str(fileNumber) + '.csv', index=False)
        print('Done')