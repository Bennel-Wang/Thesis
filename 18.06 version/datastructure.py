import collections

fileNumber = 1
windowTime = 40*60     #the minumum interval between steps
aggregationWin = 20*60
decayPeriod = 1
alpha = 0.8
simT = 0.9
fT = 1
resultList = []
windowList = []
endList = ['Stream_DoS']

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
knowledgeMatrix[('Email_Ehlo','Email_Ehlo')] = -1
knowledgeMatrix[('Email_Ehlo','Email_Almail_Overflow')] = -1
knowledgeMatrix[('Email_Almail_Overflow','Email_Almail_Overflow')] = -1
knowledgeMatrix[('Email_Almail_Overflow','Email_Ehlo')] = -1
knowledgeMatrix[('TelnetTerminaltype','Email_Almail_Overflow')] = -1
knowledgeMatrix[('TelnetTerminaltype','Email_Ehlo')] = -1
knowledgeMatrix[('Email_Almail_Overflow', 'TelnetTerminaltype')] = -1
knowledgeMatrix[('Email_Ehlo', 'TelnetTerminaltype')] = -1
knowledgeMatrix[('Email_Ehlo', 'Email_Turn')] = -1
knowledgeMatrix[('Email_Ehlo', 'Email_Debug')] = -1
knowledgeMatrix[('Email_Ehlo', 'FTP_User')] = -1
knowledgeMatrix[('Email_Ehlo', 'Rsh')] = -1
knowledgeMatrix[('Email_Debug', 'Email_Ehlo')] = -1
knowledgeMatrix[('Start','Email_Debug')] = -1
knowledgeMatrix[('Email_Almail_Overflow', 'Rsh')] = -1
knowledgeMatrix[('FTP_User', 'Email_Ehlo')] = -1
knowledgeMatrix[('FTP_Pass', 'Email_Ehlo')] = -1
knowledgeMatrix[('FTP_Syst', 'Email_Ehlo')] = -1
#knowledge - based precorrelation
knowledgeMatrix[('Mstream_Zombie','Stream_DoS')] = 0.9
knowledgeMatrix[('Mstream_Zombie','Port_Scan')] = 0.9
knowledgeMatrix[('Sadmind_Amslverify_Overflow','FTP_Pass')] = 0.3
knowledgeMatrix[('Sadmind_Amslverify_Overflow','FTP_Put')] = 0.3
knowledgeMatrix[('Sadmind_Amslverify_Overflow','FTP_User')] = 0.3