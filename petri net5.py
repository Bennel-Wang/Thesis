from pm4py.objects.petri.petrinet import PetriNet, Marking
net5 = PetriNet("stage5")

# creating Start, End
Start = PetriNet.Place("Start")
P1 = PetriNet.Place("P1")
P2 = PetriNet.Place("P2")
P3 = PetriNet.Place("P3")
End = PetriNet.Place("End")
# add the places to the Petri Net
net5.places.add(Start)
net5.places.add(P1)
net5.places.add(P2)
net5.places.add(P3)
net5.places.add(End)

# Create transitions
t_1 = PetriNet.Transition("t1", "TCP")
t_2 = PetriNet.Transition("t2", "TELNET")
t_3 = PetriNet.Transition("t3", "UDP")
t_4 = PetriNet.Transition("t4", "ICMP")
net5.transitions.add(t_1)
net5.transitions.add(t_2)
net5.transitions.add(t_3)
net5.transitions.add(t_4)

# Add arcs
from pm4py.objects.petri import utils
utils.add_arc_from_to(Start, t_1, net5)
utils.add_arc_from_to(t_1, Start, net5)
utils.add_arc_from_to(t_1, P1, net5)
utils.add_arc_from_to(P1, t_2, net5)
utils.add_arc_from_to(t_2, Start, net5)
utils.add_arc_from_to(t_2, P2, net5)
utils.add_arc_from_to(P2, t_3, net5)
utils.add_arc_from_to(t_3, P3, net5)
utils.add_arc_from_to(P3, t_4, net5)
utils.add_arc_from_to(t_4, End, net5)

# Adding tokens
initial_marking = Marking()
initial_marking[Start] = 'Start'
final_marking = Marking()
final_marking[End] = 'End'

from pm4py.objects.petri.exporter import exporter as pnml_exporter
pnml_exporter.apply(net5, initial_marking, "/home/jin/Documents/stage5.pnml", final_marking=final_marking)

from pm4py.visualization.petrinet import visualizer as pn_visualizer
parameters = {pn_visualizer.Variants.WO_DECORATION.value.Parameters.FORMAT: "svg"}
gviz = pn_visualizer.apply(net5, initial_marking, final_marking, parameters=parameters)
pn_visualizer.save(gviz, "/home/jin/Documents/stage5.svg")

print('Done')