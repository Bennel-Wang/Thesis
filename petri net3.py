from pm4py.objects.petri.petrinet import PetriNet, Marking
net3 = PetriNet("stage3")

# creating Start, End
Start = PetriNet.Place("Start")
P1 = PetriNet.Place("P1")
P2 = PetriNet.Place("P2")
End = PetriNet.Place("End")
# add the places to the Petri Net
net3.places.add(Start)
net3.places.add(P1)
net3.places.add(P2)
net3.places.add(End)

# Create transitions
t_1 = PetriNet.Transition("t1", "TCP")
t_2 = PetriNet.Transition("t2", "FTP")
t_3 = PetriNet.Transition("t3", "FTP-Data")
net3.transitions.add(t_1)
net3.transitions.add(t_2)
net3.transitions.add(t_3)

# Add arcs
from pm4py.objects.petri import utils
utils.add_arc_from_to(Start, t_1, net3)
utils.add_arc_from_to(t_1, Start, net3)
utils.add_arc_from_to(t_1, P1, net3)
utils.add_arc_from_to(t_1, P2, net3)
utils.add_arc_from_to(t_1, End, net3)
utils.add_arc_from_to(P1, t_2, net3)
utils.add_arc_from_to(t_2, P1, net3)
utils.add_arc_from_to(t_2, Start, net3)
utils.add_arc_from_to(t_2, P2, net3)
utils.add_arc_from_to(P2, t_3, net3)
utils.add_arc_from_to(t_3, P2, net3)
utils.add_arc_from_to(t_3, Start, net3)

# Adding tokens
initial_marking = Marking()
initial_marking[Start] = 'Start'
final_marking = Marking()
final_marking[End] = 'End'

from pm4py.objects.petri.exporter import exporter as pnml_exporter
pnml_exporter.apply(net3, initial_marking, "/home/jin/Documents/stage3.pnml", final_marking=final_marking)

from pm4py.visualization.petrinet import visualizer as pn_visualizer
parameters = {pn_visualizer.Variants.WO_DECORATION.value.Parameters.FORMAT: "svg"}
gviz = pn_visualizer.apply(net3, initial_marking, final_marking, parameters=parameters)
pn_visualizer.save(gviz, "/home/jin/Documents/stage3.svg")

print('Done')