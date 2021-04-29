import csv
import pandas as pd

def timeConversion(Time):
    [h,m,s] = Time.split(':')
    t = 60*(float(m) + 60*float(h)) + float(s)
    return t

def hyperAlertGrouping():
    with open('/home/jin/Documents/Generated Data/record1.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                record = [{'Time': '0:0:0', 'lastAlert': 'Start','currAlert': 'Start', 'SrcIp': 'xxx.xxx.xxx.xxx', 'DesIp': 'xxx.xxx.xxx.xxx'}]
                pointer = 0
                result = []
                continue
            else:
                l = {'Time': l[1], 'lastAlert': l[2], 'currAlert': l[3], 'fitness': l[4], 'SrcIp': l[5], 'DesIp': l[6], 'probability':l[7], 'remain-lastRemain':l[8]}
                #print(l)
                for i in range(0,len(result)):
                    #gap = timeConversion(l['Time']) - timeConversion(result[i][0])
                    if((l['lastAlert'] == result[i][1]) and (l['currAlert'] == result[i][2])):
                        if (l['SrcIp'] == result[i][4]) and (l['DesIp'] == result[i][5]):
                            #print(gap)
                            break   #group
                        #elif (l['SrcIp'] in result[i][4]):
                        #    result[i][5].append(l['DesIp'])
                        #elif (l['DesIp'] in result[i][5]):
                        #    result[i][4].append(l['SrcIp'])
                        #    break   #group
                else:   #all with not satisfy
                    result.append([l['Time'], l['lastAlert'], l['currAlert'], l['fitness'], l['SrcIp'], l['DesIp']])
                #record.append(
                #    {'Time': l['Time'], 'lastAlert': l['lastAlert'], 'currAlert': l['currAlert'], 'SrcIp': l['SrcIp'],
                #     'DesIp': l['DesIp']})
        name = ['Time', 'lastAlert', 'currAlert', 'fitness', 'SrcIp', 'DesIp']
        data = pd.DataFrame(columns=name, data=result)
        data.to_csv('/home/jin/Documents/Generated Data/record1-hyper.csv')
            # break


