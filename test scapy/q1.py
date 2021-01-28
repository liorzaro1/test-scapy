from scapy.all import *

a = sniff()
rdpcap('nisoy.pcap',a)
print(a)

def check_is(p):
    if TCP in a > UDP in a
        return true
    elif 
        UDP in a > TCP in a 
        return false



