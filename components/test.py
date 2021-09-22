from sys import setdlopenflags
from ctypes import RTLD_GLOBAL
setdlopenflags (RTLD_GLOBAL | 2)

from members_component import Leg
from animal_component import Pet
from component_Hachage import component_Hachage
from signature_component import Signature

s = Signature()

p=Pet("medor chien")
l=Leg("front left")
l2=Leg("avant droite")
p.addLeg(l)
p.addLeg(l2)
print(p.to_json())
