# 1.2
#a simple spoofing program that spoof icmp request to the host in the local network
from scapy.all import*
iphdr = IP()
iphdr.dst = '10.9.0.5' #host ip
iphdr.src = '10.9.0.1' #attacker ip
icmphdr = ICMP()
pkt = iphdr/icmphdr
send(pkt)
