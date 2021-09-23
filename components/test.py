from sys import setdlopenflags
from ctypes import RTLD_GLOBAL
setdlopenflags (RTLD_GLOBAL | 2)


from component_Hachage import component_Hachage
from signature_component import Signature

s = Signature()
print(s.signMessage("abc", "abc"))
