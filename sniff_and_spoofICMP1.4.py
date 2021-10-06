# 1.14
# sniffing ping requests and sending spoofed reply
from scapy.all import*
def print_pkt(pkt):
	iphdr = pkt[0][1]  #make the fake iphdr for the fake pkt
	icmphdr = pkt[0][2] #make the fake icmphdr for the fake pkt

	pkt.show()
	icmphdr.chksum = None # reset the chksum
	temp = iphdr.src 
	iphdr.src = iphdr.dst
	iphdr.dst = temp # swap the src ip with the dst ip
	icmphdr.type = 'echo-reply'# change the type to reply
	send(iphdr/icmphdr) 
		
pkt = sniff(iface="br-3bef0344ba07", filter="icmp", prn=print_pkt)
