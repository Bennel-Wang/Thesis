import collections
import csv
import os
import para
import helperfunc
import petrinet

def tokenReplay():
    file_dir = '/home/jin/Documents/Iptree/scenario' + str(para.fileNumber) + '/'
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            windowList = []
            alertFreq = collections.defaultdict(int)
            patternFreq = collections.defaultdict(int)
            petrinetPlace = collections.defaultdict(float)
            tokenList = [0,0,0,0]   #p,c,m,r
            with open(file_dir+ str(file), 'r') as f:
                reader = csv.reader(f)
                for (j, l) in enumerate(reader):
                # remove the head
                    if (j == 0):
                        continue
                    else:
                        l = {'Time': l[0],'AlertType':l[1],'SrcIp':l[2],'DesIp':l[3]}
                        cor = 0
                        mostCorAlertInfo = ''
                        for alertInfo in windowList:
                            alertTime, alertType = alertInfo.split('-')
                            timeInt = abs(helperfunc.timeConversion(l['Time']) - helperfunc.timeConversion(alertTime))
                            #freqGap = abs(alertFreq[l['AlertType']] - alertFreq[alertType])
                            prop = (patternFreq[(alertType, l['AlertType'])]+0.001)/(alertFreq[l['AlertType']]+0.001)
                            newCor = helperfunc.correlationEstimation(timeInt,prop)
                            #print(newCor,alertInfo, str(l['Time']) + '-' + l['AlertType'])
                            #print(patternFreq)
                            if newCor>0.5:
                                #print(alertInfo,str(l['Time']) + '-' +l['AlertType'],newCor)
                                petrinet.consumeToken(petrinetPlace, alertInfo, tokenList, newCor)

                            #if cor <= newCor:
                                #cor = newCor
                                #mostCorAlertInfo = alertInfo
                        helperfunc.windowUpdate(windowList, str(l['Time']) + '-' + l['AlertType'], alertFreq,patternFreq)

                        petrinet.produceToken(petrinetPlace,str(l['Time']) + '-' + l['AlertType'], tokenList, 1)
                        #print(petrinetPlace)
                        tokenList[3] = tokenList[0] - tokenList[1] + tokenList[2]
                        #print(tokenList)
                        fitness = petrinet.fitnessCal(tokenList)
                        print(fitness, 'file', para.fileNumber, 'tree', file)

