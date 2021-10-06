# 1.1B
#sniffing local interface and filtering remote network transmition
from scapy.all import*
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface="br-92b0f2de5660", filter="net 128.230.0.0/16", prn=print_pkt)
