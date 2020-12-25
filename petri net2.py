from pm4py.objects.petri.petrinet import PetriNet, Marking
net2 = PetriNet("stage2")

# creating Start, End
Start = PetriNet.Place("Start")
P1 = PetriNet.Place("P1")
End = PetriNet.Place("End")
# add the places to the Petri Net
net2.places.add(Start)
net2.places.add(P1)
net2.places.add(End)

# Create transitions
t_1 = PetriNet.Transition("t1", "Portmap")
t_2 = PetriNet.Transition("t2", "SADMIND")
net2.transitions.add(t_1)
net2.transitions.add(t_2)

# Add arcs
from pm4py.objects.petri import utils
utils.add_arc_from_to(Start, t_1, net2)
utils.add_arc_from_to(t_1, Start, net2)
utils.add_arc_from_to(t_1,P1, net2)
utils.add_arc_from_to(P1,t_2, net2)
utils.add_arc_from_to(t_2,Start, net2)
utils.add_arc_from_to(t_2, End, net2)


# Adding tokens
initial_marking = Marking()
initial_marking[Start] = 'Start'
final_marking = Marking()
final_marking[End] = 'End'

from pm4py.objects.petri.exporter import exporter as pnml_exporter
pnml_exporter.apply(net2, initial_marking, "/home/jin/Documents/stage2.pnml", final_marking=final_marking)

from pm4py.visualization.petrinet import visualizer as pn_visualizer
parameters = {pn_visualizer.Variants.WO_DECORATION.value.Parameters.FORMAT: "svg"}
gviz = pn_visualizer.apply(net2, initial_marking, final_marking, parameters=parameters)
pn_visualizer.save(gviz, "/home/jin/Documents/stage2.svg")

print('Done')