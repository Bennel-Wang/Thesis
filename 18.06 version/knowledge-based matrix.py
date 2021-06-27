import collections
knowledgeMatrix = collections.defaultdict(float)

knowledgeMatrix[('Sadmind_Ping','Admind')] = 0.5
knowledgeMatrix[('Sadmind_Ping','Sadmind_Amslverify_Overflow')] = 0.5
knowledgeMatrix[('Sadmind_Ping','Rsh')] = 0.25
knowledgeMatrix[('Sadmind_Ping','Mstream_Zombie')] = 0.25
knowledgeMatrix[('Sadmind_Ping','Email_Debug')] = 0.25
knowledgeMatrix[('Sadmind_Ping','TelnetXdisplay')] = 0.25

knowledgeMatrix[('TelnetTerminaltype','Admind')] = 0.5
knowledgeMatrix[('TelnetTerminaltype','Email_Almail_Overflow')] = 0.5
knowledgeMatrix[('TelnetTerminaltype','Email_Ehlo')] = 0.5
knowledgeMatrix[('TelnetTerminaltype','FTP_User')] = 0.5
knowledgeMatrix[('TelnetTerminaltype','FTP_Syst')] = 0.5
knowledgeMatrix[('TelnetTerminaltype','Admind')] = 0.25
knowledgeMatrix[('TelnetTerminaltype','Sadmind_Amslverify_Overflow')] = 0.25
knowledgeMatrix[('TelnetTerminaltype','Rsh')] = 0.25
knowledgeMatrix[('TelnetTerminaltype','Mstream_Zombie')] = 0.25
knowledgeMatrix[('TelnetTerminaltype','SSH_Detected')] = 0.25
knowledgeMatrix[('TelnetTerminaltype','Email_Debug')] = 0.25
knowledgeMatrix[('TelnetTerminaltype','TelnetEnvAll')] = 0.25

knowledgeMatrix[('Email_Almail_Overflow','TelnetTerminaltype')] = 0.5
knowledgeMatrix[('Email_Almail_Overflow','Email_Almail_Overflow')] = 0.5
knowledgeMatrix[('Email_Almail_Overflow','Email_Ehlo')] = 0.5
knowledgeMatrix[('Email_Almail_Overflow','FTP_User')] = 0.5
knowledgeMatrix[('Email_Almail_Overflow','FTP_Pass')] = 0.5
knowledgeMatrix[('Email_Almail_Overflow','FTP_Syst')] = 0.5
knowledgeMatrix[('Email_Almail_Overflow','Rsh')] = 0.25
knowledgeMatrix[('Email_Almail_Overflow','Email_Debug')] = 0.25

knowledgeMatrix[('Email_Ehlo','Email_Almail_Overflow')] = 0.5
knowledgeMatrix[('Email_Ehlo','Email_Ehlo')] = 0.5
knowledgeMatrix[('Email_Ehlo','FTP_User')] = 0.5
knowledgeMatrix[('Email_Ehlo','FTP_Pass')] = 0.5
knowledgeMatrix[('Email_Ehlo','FTP_Syst')] = 0.5
knowledgeMatrix[('Email_Ehlo','HTTP_Java')] = 0.5
knowledgeMatrix[('Email_Ehlo','Admind')] = 0.25
knowledgeMatrix[('Email_Ehlo','Sadmind_Amslverify_Overflow')] = 0.25
knowledgeMatrix[('Email_Ehlo','Rsh')] = 0.25
knowledgeMatrix[('Email_Ehlo','HTTP_Cisco_Catalyst_Exec')] = 0.25
knowledgeMatrix[('Email_Ehlo','SSH_Detected')] = 0.5
knowledgeMatrix[('Email_Ehlo','Email_Debug')] = 0.5

knowledgeMatrix[('FTP_User','Email_Almail_Overflow')] = 0.5
knowledgeMatrix[('FTP_User','Email_Ehlo')] = 0.25
knowledgeMatrix[('FTP_User','FTP_User')] = 0.5
knowledgeMatrix[('FTP_User','FTP_Pass')] = 0.5
knowledgeMatrix[('FTP_User','FTP_Syst')] = 0.5
knowledgeMatrix[('FTP_User','HTTP_Cisco_Catalyst_Exec')] = 0.25
knowledgeMatrix[('FTP_User','Email_Debug')] = 0.25

knowledgeMatrix[('FTP_Pass','TelnetTerminaltype')] = 0.5
knowledgeMatrix[('FTP_Pass','Email_Ehlo')] = 0.5
knowledgeMatrix[('FTP_Pass','FTP_User')] = 0.5
knowledgeMatrix[('FTP_Pass','FTP_Pass')] = 0.5
knowledgeMatrix[('FTP_Pass','FTP_Syst')] = 0.5
knowledgeMatrix[('FTP_Pass','Email_Debug')] = 0.25

knowledgeMatrix[('FTP_Syst','TelnetTerminaltype')] = 0.5
knowledgeMatrix[('FTP_Syst','Email_Ehlo')] = 0.5
knowledgeMatrix[('FTP_Syst','FTP_User')] = 0.5
knowledgeMatrix[('FTP_Syst','FTP_Pass')] = 0.5
knowledgeMatrix[('FTP_Syst','FTP_Syst')] = 0.5
knowledgeMatrix[('FTP_Syst','HTTP_Cisco_Catalyst_Exec')] = 0.25
knowledgeMatrix[('FTP_Syst','SSH_Detected')] = 0.25

knowledgeMatrix[('HTTP_Java','TelnetTerminaltype')] = 0.5
knowledgeMatrix[('HTTP_Java','Email_Ehlo')] = 0.5
knowledgeMatrix[('HTTP_Java','FTP_User')] = 0.25
knowledgeMatrix[('HTTP_Java','FTP_Pass')] = 0.25
knowledgeMatrix[('HTTP_Java','FTP_Syst')] = 0.25
knowledgeMatrix[('HTTP_Java','HTTP_Java')] = 0.5
knowledgeMatrix[('HTTP_Java','HTTP_Shells')] = 0.25

knowledgeMatrix[('HTTP_Shells','HTTP_Java')] = 0.25

knowledgeMatrix[('Admind','Admind')] = 0.5
knowledgeMatrix[('Admind','Sadmind_Amslverify_Overflow')] = 0.5
knowledgeMatrix[('Admind','Rsh')] = 0.5
knowledgeMatrix[('Admind','Mstream_Zombie')] = 0.5
knowledgeMatrix[('Admind','TelnetXdisplay')] = 0.25
knowledgeMatrix[('Admind','TelnetEnvAll')] = 0.25

knowledgeMatrix[('Sadmind_Amslverify_Overflow','Admind')] = 0.5
knowledgeMatrix[('Sadmind_Amslverify_Overflow','Sadmind_Amslverify_Overflow')] = 0.5
knowledgeMatrix[('Sadmind_Amslverify_Overflow','Rsh')] = 0.5
knowledgeMatrix[('Sadmind_Amslverify_Overflow','Mstream_Zombie')] = 0.5
knowledgeMatrix[('Sadmind_Amslverify_Overflow','TelnetXdisplay')] = 0.25
knowledgeMatrix[('Sadmind_Amslverify_Overflow','TelnetEnvAll')] = 0.25

knowledgeMatrix[('Rsh','Rsh')] = 0.5
knowledgeMatrix[('Rsh','Mstream_Zombie')] = 0.25
knowledgeMatrix[('Rsh','TelnetXdisplay')] = 0.25
knowledgeMatrix[('Rsh','TelnetEnvAll')] = 0.25

knowledgeMatrix[('Mstream_Zombie','Mstream_Zombie')] = 0.5
knowledgeMatrix[('Mstream_Zombie','Stream_DoS')] = 0.5

knowledgeMatrix[('HTTP_Cisco_Catalyst_Exec','HTTP_Cisco_Catalyst_Exec')] = 0.25

knowledgeMatrix[('SSH_Detected','Email_Ehlo')] = 0.25
knowledgeMatrix[('SSH_Detected','SSH_Detected')] = 0.25
knowledgeMatrix[('SSH_Detected','Email_Debug')] = 0.25

knowledgeMatrix[('Email_Debug','Email_Ehlo')] = 0.25
knowledgeMatrix[('Email_Debug','FTP_Pass')] = 0.25

knowledgeMatrix[('TelnetXdisplay','Mstream_Zombie')] = 0.5
knowledgeMatrix[('TelnetXdisplay','TelnetEnvAll')] = 0.25

knowledgeMatrix[('TelnetEnvAll','Mstream_Zombie')] = 0.5