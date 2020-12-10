import pandas as pd
from pm4py.objects.log.exporter.xes import exporter as xes_exporter
from pm4py.objects.log.importer.xes import importer as xes_importer
from pm4py.objects.conversion.log import converter as log_converter
from pm4py.algo.discovery.inductive import algorithm as inductive_miner
from pm4py.visualization.process_tree import visualizer as pt_visualizer
from pm4py.objects.log.importer.xes import importer as xes_importer
from pm4py.objects.conversion.process_tree import converter as pt_converter

log_csv = pd.read_csv('/home/jin/Documents/Generated Data/data_group1.csv', sep=',')
log_csv.rename(columns={'Ip': 'concept:name'}, inplace=True)
parameters = {log_converter.Variants.TO_EVENT_LOG.value.Parameters.CASE_ID_KEY: 'concept:name'}
event_log = log_converter.apply(log_csv, parameters=parameters, variant=log_converter.Variants.TO_EVENT_LOG)
xes_exporter.apply(event_log, '/home/jin/Documents/Generated Data/data_group1_xes.xes')

log = xes_importer.apply('/home/jin/Documents/Generated Data/data_group1_xes.xes')
tree = inductive_miner.apply_tree(log)
gviz = pt_visualizer.apply(tree)
pt_visualizer.view(gviz)