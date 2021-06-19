from tokenflow import tokenReplay
from aggregation import alertAggregation
from timezoneswitch import timeZoneSwitch
from visualization import visualization
def main():
    timeZoneSwitch()
    tokenReplay()
    alertAggregation()
    visualization()
if __name__ == '__main__':
    main()