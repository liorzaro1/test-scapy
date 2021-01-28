from scapy.all import *
num=0

def print_counter():
    global num
    num+=1
    return num

def print_info(packet):
    return packet[ether].src
    packet.show()

sniff(prn= print_info, print_counter count=10)
