import csv
import re


with open('/home/bennel/Documents/DARPA2000-LLS_DDOS_2.0.2/inside.csv', 'r') as f:
    reader = csv.reader(f)
    result = []
    for (i,l) in enumerate(reader):
        if(i == 0):
            continue

        else:
            pattern = re.compile(r'(.*)  >  (.*)')
            matchObj = pattern.match(l[6])
            if (matchObj):
                l = {'No.id': l[0], 'Time': l[1], 'SrcIp': l[2], 'DesIp': l[3], 'Protocol': l[4], 'SrcPort':matchObj.group(1),'DesPort':matchObj.group(2).split(' ')[0],'Len': l[5],
                     'Info': l[6]}
            else:
                l = {'No.id': l[0], 'Time': l[1], 'SrcIp': l[2], 'DesIp': l[3], 'Protocol': l[4], 'SrcPort':'-','DesPort':'-', 'Len': l[5],
                     'Info': l[6]}
            print(l)
        result.append(l)
