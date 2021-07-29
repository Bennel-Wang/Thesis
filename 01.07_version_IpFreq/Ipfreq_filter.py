#frequent IP tree building
import para
import helperfunc
import csv
import pandas as pd
import collections

#filter infrequent IP and build frequent IP trees
#the time window is checked manually here
def IpFilter():
    with open('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/tc_inside' + str(para.fileNumber) + '_alert.csv', 'r') as f:
        reader = csv.reader(f)
        for (j, l) in enumerate(reader):
            # remove the head
            if (j == 0):
                IpFreq = collections.defaultdict(int)  # IpFreq[(SrcIp, DesIp)] = freq
                record = collections.defaultdict(list) # record[SrcIp] = [alert information]
                res = collections.defaultdict(list)    #result[treeNum] = [list of record[SrcIp]]
                tree = collections.defaultdict(int)    #tree[Ip] = TreeNumber
                preCorAlert = []
                continue
            else:
                l = {'Time': l[0], 'SrcIp': l[2], 'DesIp': l[4], 'Alert': l[5],'SeqNum':j}
                IpFreq[(l['SrcIp'], l['DesIp'])] = IpFreq[(l['SrcIp'], l['DesIp'])] + 1     #update frequency
                record[l['SrcIp']].append([l['Time'], l['Alert'],l['SrcIp'], l['DesIp'], l['SeqNum']])

        #build IP tree
        maxTreeNum = 0                      #current maximum tree number, increase with new tree
        merge = []
        for (Ip1,Ip2) in IpFreq.keys():     #tree building or merging
            if IpFreq[(Ip1, Ip2)] >= para.IpNumT:       #if frequency is bigger than threshold and alert number is bigger than the minimum number that can form a multi-step attack
                if tree[Ip1] == 0 and tree[Ip2] == 0:
                    maxTreeNum = maxTreeNum + 1          #build new tree
                    tree[Ip1] = maxTreeNum
                    tree[Ip2] = maxTreeNum
                elif tree[Ip1] == 0 and tree[Ip2] != 0:  #merge the tree
                    tree[Ip1] = tree[Ip2]
                elif tree[Ip1] != 0 and tree[Ip2] == 0:  #merge the tree
                    tree[Ip2] = tree[Ip1]
                else:
                    merge.append([tree[Ip1], tree[Ip2]])

                res[tree[Ip1]] = res[tree[Ip1]] + record[Ip1]       #merge two lists
                res[tree[Ip2]] = res[tree[Ip2]] + record[Ip2]
                record[Ip1] = []
                record[Ip2] = []
                res[tree[Ip1]].sort(key = helperfunc.takeTime)  #ranking
                res[tree[Ip2]].sort(key = helperfunc.takeTime)

        mergeDict = collections.defaultdict(int)
        for t1, t2 in merge:
            if mergeDict[t2] == 0:  #has not been merge before
                print('merge tree', t1, 'and tree', t2, 'to tree', t1)  # merge tree
                res[t1] = res[t1] + res[t2]
                res[t2] = []
            else:
                print('merge tree', t1, 'and tree', mergeDict[t2], 'to tree', t1)  # merge tree
                res[t1] = res[t1] + res[mergeDict[t2]]
                res[mergeDict[t2]] = []
                res[t2] = []
            mergeDict[t2] = t1

        for f in range(maxTreeNum+1):
            if f == 0 or len(res[f])==0:  #empty file
                continue
            name = ['Time', 'Alert', 'SrcIp', 'DesIp', 'Original Seq Num']
            data = pd.DataFrame(columns=name, data=res[f])
            data.to_csv('/home/jin/Documents/Iptree/scenario'+str(para.fileNumber) + '/tree_' + str(f) + '.csv', index=False)
        print('Done')




