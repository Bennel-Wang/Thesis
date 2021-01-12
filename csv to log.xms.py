import pandas as pd
from pm4py.objects.log.exporter.xes import exporter as xes_exporter
from pm4py.objects.conversion.log import converter as log_converter
from pm4py.algo.discovery.inductive import algorithm as inductive_miner
from pm4py.visualization.process_tree import visualizer as pt_visualizer
from pm4py.objects.log.importer.xes import importer as xes_importer
from pm4py.objects.conversion.process_tree import converter as pt_converter
from pm4py.objects.log.util import dataframe_utils

log_csv = pd.read_csv('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/phase1.csv', sep=',')
log_csv = dataframe_utils.convert_timestamp_columns_in_df(log_csv)
log_csv = log_csv.sort_values('Time')
log_csv.rename(columns={'Protocol': 'concept:name'}, inplace=True)
parameters = {log_converter.Variants.TO_EVENT_LOG.value.Parameters.CASE_ID_KEY: 'concept:name'}
event_log = log_converter.apply(log_csv, parameters=parameters, variant=log_converter.Variants.TO_EVENT_LOG)
xes_exporter.apply(event_log, '/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/phase1.xes')

log = xes_importer.apply('/home/jin/Documents/DARPA2000-LLS_DDOS_2.0.2/phase1.xes')
tree = inductive_miner.apply_tree(log)
gviz = pt_visualizer.apply(tree)
pt_visualizer.view(gviz)

from pm4py.algo.discovery.heuristics import algorithm as heuristics_miner
heu_net = heuristics_miner.apply_heu(log, parameters={heuristics_miner.Variants.CLASSIC.value.Parameters.DEPENDENCY_THRESH: 0.99})
from pm4py.visualization.heuristics_net import visualizer as hn_visualizer
gviz = hn_visualizer.apply(heu_net)
hn_visualizer.view(gviz)

#net, im, fm = heuristics_miner.apply(log, parameters={heuristics_miner.Variants.CLASSIC.value.Parameters.DEPENDENCY_THRESH: 0.99})
net, im, fm = pt_converter.apply(tree, variant=pt_converter.Variants.TO_PETRI_NET)
from pm4py.visualization.petrinet import visualizer as pn_visualizer
gviz = pn_visualizer.apply(net, im, fm)
pn_visualizer.view(gviz)

#from pm4py.objects.conversion.process_tree import converter as pt_converter
#net, initial_marking, final_marking = pt_converter.apply(tree, variant=pt_converter.Variants.TO_PETRI_NET)