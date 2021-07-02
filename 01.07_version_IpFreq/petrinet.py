def produceToken(petriNetPlace, transition, tokenList, w):
    petriNetPlace[transition] = petriNetPlace[transition] + float(w)
    tokenList[0] = tokenList[0] + 1
    return

def consumeToken(petriNetPlace, transition, tokenList, w):
    tokenList[1] = tokenList[1] + w
    if petriNetPlace[transition] - float(w) >= 0:
        petriNetPlace[transition] = petriNetPlace[transition] - float(w)
    else:
        tokenList[2] = tokenList[2] + float(w) - petriNetPlace[transition]
        petriNetPlace[transition] = 0
    return

def fitnessCal(tokenList):
    delta = 0.0001
    [p,c,m,r] = tokenList
    return (1-r/(p+delta))
