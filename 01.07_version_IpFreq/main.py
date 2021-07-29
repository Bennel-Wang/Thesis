#main function
from Ipfreq_filter import IpFilter
from treevisualization import treeVisualization
from tokenReplay import tokenReplay
from attackGraphVisualization import resultVisualization
from attackGraphVisualization import labelVisualization
from attackGraphVisualization import originalVisualization
from aggregation import alertAggregation
from aggregation import labelAlertAggregation
def main():
    #labelAlertAggregation()
    #originalVisualization()
    #labelVisualization()
    #treeVisualization()
    #IpFilter()
    tokenReplay()
    #alertAggregation()
    #resultVisualization()
if __name__ == '__main__':
    main()