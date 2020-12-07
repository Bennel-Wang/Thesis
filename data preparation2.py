import csv
import re
import collections

#whether the gap of two inputs is bigger the the preset value
def validTimeGap(timeFormer, timeLatter, validGap):
    if timeLatter - timeFormer > validGap:
        return False
    else:
        return True

if __name__ == '__main__':

    #initialization
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/inside (test).csv', 'r') as f:
        reader = csv.reader(f)
        result = []
        infoList = [{}]
        srcIpCount = collections.defaultdict(int)   #srcIpCount[SrcIp]= Count
        desIpCount = collections.defaultdict(int)   #desIpCount[DesIp]= Count
        pathInfo = collections.defaultdict(list)    #pathInfo[SrcIp] =[[DesIp1,time1,No.id],[DesIp2,time2,No.id],[DesIp3,time3, No.id]...]
        for (i,l) in enumerate(reader):

            # remove the head
            if(i == 0):
                continue
            else:

                # get the data, re-organize them
                pattern = re.compile(r'(.*)  >  (.*)')
                matchObj = pattern.match(l[6])
                if (matchObj):
                    l = {'No.id': l[0], 'Time': l[1], 'SrcIp': l[2], 'DesIp': l[3], 'Protocol': l[4], 'SrcPort':matchObj.group(1),'DesPort':matchObj.group(2).split(' ')[0],'Len': l[5],
                         'Info': l[6]}
                else:
                    l = {'No.id': l[0], 'Time': l[1], 'SrcIp': l[2], 'DesIp': l[3], 'Protocol': l[4], 'SrcPort':'-','DesPort':'-', 'Len': l[5],
                         'Info': l[6]}
                infoList.append(l)

                srcIpCount[l['SrcIp']] = srcIpCount[l['SrcIp']] + 1
                desIpCount[l['DesIp']] = desIpCount[l['DesIp']] + 1
                if (srcIpCount[l['SrcIp']] == 1):
                    pathInfo[l['SrcIp']].append([l['DesIp'], l['Time'], l['No.id']])
        print(srcIpCount)