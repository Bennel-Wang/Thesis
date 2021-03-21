#In: time in string, validGap in float
#out: T/F for valid gap
#Function: whether the gap between two time less than the preset value
def validTimeGap(timeFormer, timeLatter, validGap):
    if float(timeLatter) - float(timeFormer) > validGap:
        return False
    else:
        return True

#In: Attack Pattern Petri Net to be detected,  Protocol
#Out: list of transitting attack the protocol belongs to, false for not in all attack pattern
#Function: whether the protocol belongs to activity of the transitting attack pattern
def isProPattern(AttackNet,Protocol):
    for prot in AttackNet:
        if prot == Protocol:
            return True
    else:
        return False