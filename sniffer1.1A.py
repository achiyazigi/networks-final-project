# 1.1A
# sniffing icmp packets
from scapy.all import*
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface="br-92b0f2de5660", filter="icmp", prn=print_pkt)
