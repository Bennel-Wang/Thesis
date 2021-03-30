#petri net model to be detected
DNSServer_P = {'1*Start': [], '1*End': []}                                      #place list = [place: [production time list]]
DNSServer_T = ['2*DNS', '1*SA']                                                 # transition list
DNSServer_A1 = [['1*Start', '2*DNS', float('inf')], ['1*End', '1*SA', 1]]       #arc list1 = [place, transition, consumption deadline]
DNSServer_A2 = [['2*DNS', '1*End', 0], ['1*SA', '1*Start', 0]]                  #arc list2 = [transition, place, production delay]
DNSServer_L = 2                                                                #length of sequence (control effect not perfect)----or can we use fitness and length together as step transition conditions?

BreakSAD_P = {'1*Start': [], '1*P1': [], '1*End': []}
BreakSAD_T = ['2*Portmap', '1*SADMIND', '1*SA']
BreakSAD_A1 = [['1*Start', '2*Portmap', float('inf')], ['1*P1', '1*SADMIND', 0.1], ['1*End', '1*SA', 10]]
BreakSAD_A2 = [['2*Portmap', '1*P1', 0], ['1*SADMIND', '1*End', 0], ['1*SA', '1*Start', 0]]
BreakSAD_L = 4

FTPUpload_P = {'1*Start': [], '1*End': []}
FTPUpload_T = ['1*FTP-DATA', '1*SA']
FTPUpload_A1 = [['1*Start', '1*FTP-DATA', float('inf')], ['1*End', '1*SA', 10]]
FTPUpload_A2 = [['1*FTP-DATA', '1*End', 0], ['1*SA', '1*Start', 0]]
FTPUpload_L = 30

LauDDoS_P = {'1*Start': [], '1*End': []}
LauDDoS_T = ['1*TELNET', '1*SA']
LauDDoS_A1 = [['1*Start', '1*TELNET', float('inf')], ['1*End', '1*SA', 100]]
LauDDoS_A2 = [['1*TELNET', '1*End', 0], ['1*SA', '1*Start', 0]]
LauDDoS_L = 50

transitionSet = set(DNSServer_T + BreakSAD_T + FTPUpload_T + LauDDoS_T + FTPUpload_T + LauDDoS_T)

Attack1_T = [DNSServer_T, BreakSAD_T, FTPUpload_T, LauDDoS_T, FTPUpload_T, LauDDoS_T]
Attack1_P = [DNSServer_P.copy(), BreakSAD_P.copy(), FTPUpload_P.copy(), LauDDoS_P.copy(), FTPUpload_P.copy(),
             LauDDoS_P.copy()]
Attack1_A1 = [DNSServer_A1, BreakSAD_A1, FTPUpload_A1, LauDDoS_A1, FTPUpload_A1, LauDDoS_A1]
Attack1_A2 = [DNSServer_A2, BreakSAD_A2, FTPUpload_A2, LauDDoS_A2, FTPUpload_A2, LauDDoS_A2]
Attack1_L = [DNSServer_L, BreakSAD_L, FTPUpload_L, LauDDoS_L, 5, LauDDoS_L]

Attack1 = [Attack1_T, Attack1_P, Attack1_A1, Attack1_A2, Attack1_L]

AttackList = [Attack1]

