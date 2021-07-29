#hyperalert aggregation
import csv
import pandas as pd
import os
import para
from helperfunc import validTimeGap
from helperfunc import timeConversion
from helperfunc import timeConversionBack

#aggregation for the correlated alerts
def alertAggregation():
    file_dir = '/home/jin/Documents/FinalResult/Scenario' + str(para.fileNumber) + '/'
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            with open(file_dir + file, 'r') as f:
                reader = csv.reader(f)
                for (j, l) in enumerate(reader):
                    if (j == 0):
                        result = []
                        continue
                    else:
                        # print(l)
                        l = {'Time': timeConversion(l[0]), 'Alert': l[1], 'SrcIp': l[2], 'DesIp': l[3]}
                        for i in range(0, len(result)):
                            if (validTimeGap(timeConversion(result[i][0]), l['Time'], para.stepWinT) and l['Alert'] ==
                                    result[i][1] and l['SrcIp'] == result[i][2] and l['DesIp'] == result[i][3]):
                                result.pop(i)
                                result.append([timeConversionBack(l['Time']), l['Alert'], l['SrcIp'], l['DesIp']])
                                break
                        else:  # all with not satisfy
                            result.append([timeConversionBack(l['Time']), l['Alert'], l['SrcIp'], l['DesIp']])

                name = ['Time(after conversion)', 'Alert', 'SrcIp', 'DesIp']
                data = pd.DataFrame(columns=name, data=result)
                data.to_csv(file_dir + '_hyper' + file,
                            index=False)


#aggregation for labelled alerts
def labelAlertAggregation():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/Ground True/DDoS' + str(para.fileNumber) + '.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                result = []
                continue
            else:
                #print(l)
                l = {'Time': timeConversion(l[0]), 'Alert': l[5], 'SrcIp': l[2], 'DesIp': l[4]}
                for i in range(0,len(result)):
                    if(validTimeGap(timeConversion(result[i][0]),l['Time'], para.stepWinT) and l['Alert'] == result[i][1] and l['SrcIp'] == result[i][2] and l['DesIp'] == result[i][3]):
                        result.pop(i)
                        result.append([timeConversionBack(l['Time']), l['Alert'], l['SrcIp'], l['DesIp']])
                        break
                else:   #all with not satisfy
                    result.append([timeConversionBack(l['Time']), l['Alert'], l['SrcIp'], l['DesIp']])

        name = ['Time(after conversion)', 'Alert', 'SrcIp', 'DesIp']
        data = pd.DataFrame(columns=name, data=result)
        data.to_csv('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/aggregated_DDoS' + str(para.fileNumber) + '.csv', index = False)