# 1.3 pinging with increasing ttl untill server answers 
from scapy.all import*
iphdr = IP()

iphdr.dst = '8.8.8.8' #to google.com
icmphdr = ICMP()

for i in range(64): #until wireshark represents the reply
	iphdr.ttl = i
	pkt = iphdr/icmphdr
	send(pkt)
