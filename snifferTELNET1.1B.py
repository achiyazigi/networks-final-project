# 1.1B
#filtering dst port 23 && tcp && src 10.9.0.5
from scapy.all import*
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface="br-92b0f2de5660", filter="dst port 23 && tcp && src 10.9.0.5", prn=print_pkt)
