from IpChainConstruction import IpChainConstuct
from GroupingRule import grouping
from HyperAlertGrouping import hyperAlertGrouping
from TokenFlow import tokenReplay
def main():
    tokenReplay()
    hyperAlertGrouping()
    print('Detection done')
if __name__ == '__main__':
    main()