#token replay, select alert group, label step state
#input alerts from dataset, output selected alert group with step states labelled
import collections
import csv
import os
import para
import pandas as pd
import helperfunc
import petrinet
from time import perf_counter

def tokenReplay():
    file_dir = '/home/jin/Documents/Iptree/scenario' + str(para.fileNumber) + '/'
    #t1_start = perf_counter()                       #run time start
    for root, dirs, files in os.walk(file_dir):     #read all the frequent IP tree
        for file in files:
            windowList = []
            alertFreq = collections.defaultdict(int)
            patternFreq = collections.defaultdict(int)
            petrinetPlace = collections.defaultdict(float)
            tokenList = [0,0,0,0]   #p,c,m,r
            counter = 0 #how many record of fitness is bigger than 0.5
            res = []
            dangerous = False
            with open(file_dir+ str(file), 'r') as f:
                reader = csv.reader(f)
                for (j, l) in enumerate(reader):
                # remove the head
                    #total_count = total_count + 1   #for time calculation
                    #if total_count > 300:
                    #    break
                    if (j == 0):
                        continue
                    else:
                        l = {'Time': l[0],'AlertType':l[1],'SrcIp':l[2],'DesIp':l[3]}
                        cor = 0
                        mostCorAlertInfo = ''
                        for alertInfo in windowList:
                            alertTime, alertType, SeqNum = alertInfo.split('-')
                            timeInt = abs(helperfunc.timeConversion(l['Time']) - helperfunc.timeConversion(alertTime))
                            #freqGap = abs(alertFreq[l['AlertType']] - alertFreq[alertType])
                            prop = (patternFreq[(alertType, l['AlertType'])]+0.001)/(alertFreq[l['AlertType']]+0.001)
                            newCor = helperfunc.correlationEstimation(timeInt,prop)
                            #print(newCor,alertInfo, str(l['Time']) + '-' + l['AlertType'])
                            #print(patternFreq)
                            if newCor>0.5:          #dynamically connection
                                #print(alertInfo,str(l['Time']) + '-' +l['AlertType'],newCor)
                                petrinet.consumeToken(petrinetPlace, alertInfo, tokenList, newCor)

                        helperfunc.windowUpdate(windowList, str(l['Time']) + '-' + l['AlertType']  + '-' + str(j) , alertFreq,patternFreq)
                        petrinet.produceToken(petrinetPlace,str(l['Time']) + '-' + l['AlertType']  + '-' + str(j), tokenList, 1)
                        #print(petrinetPlace)
                        tokenList[3] = tokenList[0] - tokenList[1] + tokenList[2]
                        #print(tokenList)
                        fitness = petrinet.fitnessCal(tokenList)    #fitness/causal ratio
                        if fitness > para.fitnessT:                                         #high causal ratio
                            counter = counter + 1
                        if j > para.minRecord and counter > para.recordPercentage * j:      #long duration (of high causal ratio)
                            res.append([l['Time'], l['AlertType'], l['SrcIp'], l['DesIp'], fitness,'dangerous'])
                            dangerous = True            # true means that an action to prevent further attack is taken
                        else:
                            res.append([l['Time'], l['AlertType'], l['SrcIp'], l['DesIp'], fitness,'normal'])
            if dangerous:
                seqPetri = []
                for _,v in petrinetPlace.items():
                   seqPetri.append(v)
                stepNum = 0
                for k in range(len(res)):           #step state
                    res[k].append(seqPetri[k])
                    if seqPetri[k] <= para.tokenT:
                        if res[k - 1][-1] == 'End Step'+ str(stepNum) or res[k - 1][-1] == 'Outside Step' or k == 0:
                            stepNum = stepNum + 1
                            res[k].append('Begin Step' + str(stepNum))
                        else:
                            res[k].append('In Step'+ str(stepNum))
                    elif res[k-1][-1] == 'In Step'+ str(stepNum) or res[k-1][-1] == 'Begin Step'+ str(stepNum):
                        res[k].append('End Step'+ str(stepNum))
                    else:
                        res[k].append('Outside Step')

    #t1_end = perf_counter()
    #print('Duration', t1_end - t1_start)
                    #res[k].append(seqPetri[k])
                    #if seqPetri[k] <= para.tokenT:
                    #    if res[k-1][-1] == 'End Step' or res[k-1][-1] == 'Outside Step':
                    #        res[k - 1][-1] = 'New Step'
                    #    res[k].append('In Step')
                    #elif res[k-1][-1] != 'End Step' and res[k-1][-1] != 'Outside Step':
                    #    res[k].append('End Step')
                    #else:
                    #    res[k].append('Outside Step')
                    #print(res[k])
                name = ['time', 'alertType', 'srcip', 'desip', 'fitness', 'state', ' token', 'Step State']
                data = pd.DataFrame(columns=name, data=res)
                data.to_csv('/home/jin/Documents/FinalResult/Scenario' + str(para.fileNumber) + '/01.07_result_of_' + file,
                            index=False)
                print('Done')






