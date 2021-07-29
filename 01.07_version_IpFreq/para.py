#define various parameters in the file
import collections
import math

IpNumT = 7         #minimum number of alerts to control a zombie computer
minAlertNum = 15   #minium total alerts number in a multi-step attack scenario
fileNumber = 2     #scenario number
stepWinT = 20*60   #time window, maximun duration inside a step
expBase = 1/2      #exponiential base for time similarity
fitnessT = 0.5     #catio ratio/fitness threshold
recordPercentage = 0.6  #proportion of record meet fitness threshold
minRecord = 15     #minimus record that can be counted as dangerous (to take measures)
tokenT = 0.4       #token threshold to label in step state
