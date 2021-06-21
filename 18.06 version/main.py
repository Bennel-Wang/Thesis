from tokenflow import tokenReplay
from aggregation import alertAggregation
from timezoneswitch import timeZoneSwitch
from visualization import resultVisualization
from visualization import originVisualization
from visualization import labelVisualization
from aggregation import labelAlertAggregation

def main():
    #timeZoneSwitch()
    #originVisualization()
    #labelVisualization()
    #labelAlertAggregation()
    tokenReplay()
    alertAggregation()
    resultVisualization()
if __name__ == '__main__':
    main()