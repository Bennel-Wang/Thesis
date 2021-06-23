import collections

fileNumber = 1
windowTime = 40*60     #the minumum interval between steps
aggregationWin = 20*60
decayPeriod = 5
simT = 1    #29/32,mask
fT = 1
resultList = []
windowList = []
endList = ['Stream_DoS']
uncorrelateList = ['Email_Ehlo','Email_Almail_Overflow','Email_Turn','Email_Debug']

alertList = ['Sadmind_Ping', 'TelnetTerminaltype', 'Email_Almail_Overflow', 'Email_Ehlo', 'FTP_User', 'FTP_Pass',
            'FTP_Syst', 'HTTP_Java', 'HTTP_Shells', 'Admind', 'Sadmind_Amslverify_Overflow', 'Rsh', 'Mstream_Zombie',
            'HTTP_Cisco_Catalyst_Exec', 'SSH_Detected', 'Email_Debug', 'TelnetXdisplay', 'TelnetEnvAll', 'Stream_DoS',
            'FTP_Put', 'Email_Turn', 'HTTP_ActiveX','Port_Scan', 'TCP_Urgent_Data','RIPExpire','RIPAdd']
recordList = collections.defaultdict(list)      #recordList[i] =[[prerequisite-Time...], time, srcIp, desIp, alert...]
IpFT = collections.defaultdict(int)             #IpFT[Ip] = [freq-lastTime...]
patternMatrix = collections.defaultdict(int)    #patternMatrix[(pattern1, pattern2)] = freq
petriNetPlace = collections.defaultdict(int)    #petriNetPlace[alert-time] = tokenNum
knowledgeMatrix = collections.defaultdict(float)
#knowledge-based decorrelation
def deinitialization():
    for a in alertList:
        #knowledgeMatrix[(a, a)] = -100
        knowledgeMatrix[('Email_Ehlo',a)] = -100
        knowledgeMatrix[('Email_Debug', a)] = -100
        knowledgeMatrix[('Email_Turn', a)] = -100
        knowledgeMatrix[('Email_Almail_Overflow',a)] = -100
        knowledgeMatrix[(a,'Email_Ehlo')] = -100
        knowledgeMatrix[(a, 'Email_Turn')] = -100
        knowledgeMatrix[(a, 'Email_Debug')] = -100
        knowledgeMatrix[(a, 'Email_Almail_Overflow')] = -100
    return

#knowledge - based precorrelation
knowledgeMatrix[('Mstream_Zombie','Stream_DoS')] = 100
#knowledgeMatrix[('TelnetTerminaltype','TelnetEnvAll')] = 0.2
#knowledgeMatrix[('TelnetTerminaltype','TelnetXdisplay')] = 0.2
#knowledgeMatrix[('TelnetTerminaltype','Mstream_Zombie')] = 0.2
#knowledgeMatrix[('TelnetXdisplay','TelnetEnvAll')] = 0.2
#knowledgeMatrix[('TelnetXdisplay','TelnetTerminaltype')] = 0.2
#knowledgeMatrix[('TelnetXdisplay','Mstream_Zombie')] = 0.2
#knowledgeMatrix[('TelnetEnvAll','TelnetTerminaltype')] = 0.2
#knowledgeMatrix[('TelnetEnvAll','TelnetXdisplay')] = 0.2
#knowledgeMatrix[('TelnetEnvAll','Mstream_Zombie')] = 0.2
#knowledgeMatrix[('Sadmind_Amslverify_Overflow','Rsh')] = 0.5
#knowledgeMatrix[('Sadmind_Amslverify_Overflow','FTP_Pass')] = 0.2
#knowledgeMatrix[('Sadmind_Amslverify_Overflow','FTP_Put')] = 0.2
#knowledgeMatrix[('Sadmind_Amslverify_Overflow','FTP_User')] = 0.2
#knowledgeMatrix[('Mstream_Zombie','Port_Scan')] = 1
