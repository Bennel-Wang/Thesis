import csv
import pandas as pd
from datastructure import fileNumber
from helperfunc import timeConversion
from helperfunc import timeConversionBack

def timeZoneSwitch():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside' + str(fileNumber) + '_alert.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                result = []
                continue
            else:
                print(l)
                t = timeConversion(l[0])
                if fileNumber == 1:
                    t = int(t) + 40904
                if fileNumber == 2:
                    t = int(t) + 18488
                l[0] = timeConversionBack(t)
                result.append(l)
        name = ['time(after conversion)','srcport','srcip','desport','desip','alerttype']
        data = pd.DataFrame(columns=name, data=result)
        data.to_csv('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/tc_inside' + str(fileNumber) + '_alert.csv', index =None)
            # break


