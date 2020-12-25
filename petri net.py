from pm4py.objects.petri.petrinet import PetriNet, Marking
import csv
import collections

net = PetriNet("multi-step")

# creating Start, End
Start = PetriNet.Place("Start")
P1 = PetriNet.Place("P1")
P2 = PetriNet.Place("P2")
P3 = PetriNet.Place("P3")
P4 = PetriNet.Place("P4")
P5 = PetriNet.Place("P5")
P6 = PetriNet.Place("P6")
P7 = PetriNet.Place("P7")
P8 = PetriNet.Place("P8")
P9 = PetriNet.Place("P9")
End = PetriNet.Place("End")
# add the places to the Petri Net
net.places.add(Start)
net.places.add(P1)
net.places.add(P2)
net.places.add(P3)
net.places.add(P4)
net.places.add(P5)
net.places.add(P6)
net.places.add(P7)
net.places.add(P8)
net.places.add(P9)
net.places.add(End)

# Create transitions
t_1 = PetriNet.Transition("t1", "DNS")
t_2 = PetriNet.Transition("t2", "Portmap")
t_3 = PetriNet.Transition("t3", "SADMIND")
t_4 = PetriNet.Transition("t4", "TCP")
t_5 = PetriNet.Transition("t5", "FTP")
t_6 = PetriNet.Transition("t6", "FTP-Data")
t_7 = PetriNet.Transition("t7", "TELNET")
t_8 = PetriNet.Transition("t8", "UDP")
t_9 = PetriNet.Transition("t9", "ARP")
t_10 = PetriNet.Transition("t10", "ICMP")
net.transitions.add(t_1)
net.transitions.add(t_2)
net.transitions.add(t_3)
net.transitions.add(t_4)
net.transitions.add(t_5)
net.transitions.add(t_6)
net.transitions.add(t_7)
net.transitions.add(t_8)
net.transitions.add(t_9)
net.transitions.add(t_10)

Dict = {"Start":{'P':Start},"DNS":{'T':t_1,'P':P1}, "Portmap":{'T':t_2,'P':P2}, "SADMIND":{'T':t_3,'P':P3}, "TCP":{'T':t_4,'P':P4},"FTP":{'T':t_5,'P':P5},
      "FTP-DATA":{'T':t_6,'P':P6}, "TELNET":{'T':t_7,'P':P7}, "UDP":{'T':t_8,'P':P8}, "ARP":{'T':t_9,'P':P9}, "ICMP":{'T':t_10,'P':End}}
link = []
# Add arcs
from pm4py.objects.petri import utils
lastP = 'Start'
with open('/home/jin/Documents/Multi-Step/Multi-step.csv', 'r') as f:
    reader = csv.reader(f)
    for (i, l) in enumerate(reader):
        if (i == 0):
            continue
        else:
            Protocol = l[4]
            if ((lastP + 'P >' + Protocol + 'T') not in link):
                utils.add_arc_from_to(Dict[lastP]['P'], Dict[Protocol]['T'], net)
                link.append(lastP + 'P >' + Protocol + 'T')

            if ((Protocol + 'T >' + Protocol + 'P') not in link):
                utils.add_arc_from_to(Dict[Protocol]['T'], Dict[Protocol]['P'] , net)
                link.append(Protocol + 'T >' + Protocol + 'P')

            lastP = Protocol


# Adding tokens
initial_marking = Marking()
initial_marking[Start] = 'Start'
final_marking = Marking()
final_marking[End] = 'End'

from pm4py.objects.petri.exporter import exporter as pnml_exporter
pnml_exporter.apply(net, initial_marking, "/home/jin/Documents/Multi-Step/Multi-step.pnml", final_marking=final_marking)

from pm4py.visualization.petrinet import visualizer as pn_visualizer
parameters = {pn_visualizer.Variants.WO_DECORATION.value.Parameters.FORMAT: "svg"}
gviz = pn_visualizer.apply(net, initial_marking, final_marking, parameters=parameters)
pn_visualizer.save(gviz, "/home/jin/Documents/Multi-Step/Multi-step.svg")

print('Done')