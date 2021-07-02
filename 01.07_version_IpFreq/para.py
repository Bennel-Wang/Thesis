#define various parameters in the file
import collections

IpNumT = 1/90      #assume every 90 Ip contains 1 in the multi-step attack Ip tree
minAlertNum = 300  #minium total alerts number that contain a multi-step attack scenario
fileNumber = 1
stepWinT = 20*60    #maximun duration inside a step
expBase = 1/3
