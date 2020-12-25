from pm4py.objects.petri.petrinet import PetriNet, Marking
net4 = PetriNet("stage4")

# creating Start, End
Start = PetriNet.Place("Start")
P1 = PetriNet.Place("P1")
P2 = PetriNet.Place("P2")
P3 = PetriNet.Place("P3")
P4 = PetriNet.Place("P4")
P5 = PetriNet.Place("P5")
End = PetriNet.Place("End")
# add the places to the Petri Net
net4.places.add(Start)
net4.places.add(P1)
net4.places.add(P2)
net4.places.add(P3)
net4.places.add(P4)
net4.places.add(P5)
net4.places.add(End)

# Create transitions
t_1 = PetriNet.Transition("t1", "TCP")
t_2 = PetriNet.Transition("t2", "TELNET")
t_3 = PetriNet.Transition("t3", "Portmap")
t_4 = PetriNet.Transition("t4", "SADMIND")
t_5 = PetriNet.Transition("t5", "FTP")
t_6 = PetriNet.Transition("t6", "FTP-Data")

net4.transitions.add(t_1)
net4.transitions.add(t_2)
net4.transitions.add(t_3)
net4.transitions.add(t_4)
net4.transitions.add(t_5)
net4.transitions.add(t_6)

# Add arcs
from pm4py.objects.petri import utils
utils.add_arc_from_to(Start, t_1, net4)
utils.add_arc_from_to(t_1, Start, net4)
utils.add_arc_from_to(t_1, P1, net4)
utils.add_arc_from_to(P1, t_2, net4)
utils.add_arc_from_to(t_2, P1, net4)
utils.add_arc_from_to(t_2, Start, net4)
utils.add_arc_from_to(t_1, P2, net4)
utils.add_arc_from_to(P2, t_3, net4)
utils.add_arc_from_to(t_3, P2, net4)
utils.add_arc_from_to(t_3, P3, net4)
utils.add_arc_from_to(P3, t_4, net4)
utils.add_arc_from_to(t_4, P2, net4)
utils.add_arc_from_to(t_1, P4, net4)
utils.add_arc_from_to(P4, t_5, net4)
utils.add_arc_from_to(t_5, P4, net4)
utils.add_arc_from_to(t_5, Start, net4)
utils.add_arc_from_to(t_1, P5, net4)
utils.add_arc_from_to(P5, t_6, net4)
utils.add_arc_from_to(t_6, P5, net4)
utils.add_arc_from_to(t_6, Start, net4)
utils.add_arc_from_to(t_1, End, net4)

# Adding tokens
initial_marking = Marking()
initial_marking[Start] = 'Start'
final_marking = Marking()
final_marking[End] = 'End'

from pm4py.objects.petri.exporter import exporter as pnml_exporter
pnml_exporter.apply(net4, initial_marking, "/home/jin/Documents/stage4.pnml", final_marking=final_marking)

from pm4py.visualization.petrinet import visualizer as pn_visualizer
parameters = {pn_visualizer.Variants.WO_DECORATION.value.Parameters.FORMAT: "svg"}
gviz = pn_visualizer.apply(net4, initial_marking, final_marking, parameters=parameters)
pn_visualizer.save(gviz, "/home/jin/Documents/stage4.svg")

print('Done')