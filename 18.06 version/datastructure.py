import collections
alertList = ['Start', 'Sadmind_Ping', 'TelnetTerminaltype', 'Email_Almail_Overflow', 'Email_Ehlo', 'FTP_User', 'FTP_Pass',
            'FTP_Syst', 'HTTP_Java', 'HTTP_Shells', 'Admind', 'Sadmind_Amslverify_Overflow', 'Rsh', 'Mstream_Zombie',
            'HTTP_Cisco_Catalyst_Exec', 'SSH_Detected', 'Email_Debug', 'TelnetXdisplay', 'TelnetEnvAll', 'Stream_DoS',
            'FTP_Put', 'Email_Turn', 'HTTP_ActiveX','Port_Scan', 'TCP_Urgent_Data','RIPExpire','RIPAdd']
recordList = collections.defaultdict(list)      #recordList[i] =[[prerequisite...], time, srcIp, desIp, alert...]
IpFT = collections.defaultdict(str)             #IpFT[Ip] = [freq-lastTime...]
patternMatrix = collections.defaultdict(int)    #patternMatrix[(pattern1, pattern2)] = freq
petriNetPlace = collections.defaultdict(int)    #petriNetPlace[alert-time] = tokenNum