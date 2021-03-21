import re

#In: Data with default format
#Out: Data with specified format
#Function: Convert data into specified format
def formatConvert(data):
    pattern = re.compile(r'(.*)  >  (.*)')  #only for TCP
    matchObj = pattern.match(data[6])
    if (matchObj):
        dataDict = {'No.id': data[0], 'Time': data[1], 'SrcIp': data[2], 'DesIp': data[3], 'Protocol': data[4], 'SrcPort': matchObj.group(1),
             'DesPort': matchObj.group(2).split(' ')[0], 'Len': data[5],
             'Info': data[6]}
    else:
        dataDict = {'No.id': data[0], 'Time': data[1], 'SrcIp': data[2], 'DesIp': data[3], 'Protocol': data[4], 'SrcPort': '-',
             'DesPort': '-', 'Len': data[5],
             'Info': data[6]}
    return dataDict


