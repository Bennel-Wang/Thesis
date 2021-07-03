#define various parameters in the file
import collections
import math

IpNumT = 1/90      #assume every 90 Ip contains 1 in the multi-step attack Ip tree
minAlertNum = 300  #minium total alerts number that contain a multi-step attack scenario
fileNumber = 2
stepWinT = 20*60    #maximun duration inside a step
expBase = 1/2
fitnessT = 0.5      #fitness threshold
recordPercentage = 0.6  #how many record meet fitness threshold
minRecord = 15  #minimus record that can be counted as dangerous
tokenT = 0.4    #token threshold to label in step state
#precorrelation = {'Stream_DoS': 'Mstream_Zombie', 'Port_Scan': 'Mstream_Zombie'}   no good way to precorrelate, abandon this idea