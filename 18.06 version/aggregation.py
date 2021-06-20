import csv
import pandas as pd
from datastructure import fileNumber
from datastructure import aggregationWin
from helperfunc import validTimeGap
from helperfunc import timeConversion
from helperfunc import timeConversionBack

def alertAggregation():
    with open('/home/jin/Documents/Generated Data/1806_record' + str(fileNumber) + '.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                result = []
                continue
            else:
                print(l)
                l = {'Time': timeConversion(l[0]), 'Alert': l[1], 'SrcIp': l[2], 'DesIp': l[3],'Prerequisite': l[4]}
                for i in range(0,len(result)):
                    if(validTimeGap(timeConversion(result[i][0]),l['Time'], aggregationWin) and l['Alert'] == result[i][1] and l['SrcIp'] == result[i][2] and l['DesIp'] == result[i][3]):
                        result.pop(i)
                        result.append([timeConversionBack(l['Time']), l['Alert'], l['SrcIp'], l['DesIp'], l['Prerequisite']])
                        break
                else:   #all with not satisfy
                    result.append([timeConversionBack(l['Time']), l['Alert'], l['SrcIp'], l['DesIp'], l['Prerequisite']])

        name = ['Time(after conversion)', 'Alert', 'SrcIp', 'DesIp','Prerequisite']
        data = pd.DataFrame(columns=name, data=result)
        data.to_csv('/home/jin/Documents/Generated Data/1806_record_hyper' + str(fileNumber) + '.csv', index = False)
            # break


