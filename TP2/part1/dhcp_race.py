from scapy.all import *
IFACE = "eth0"
MY_IP = "10.1.10.200"
def handle(pkt):
    if DHCP not in pkt: return
    if pkt[DHCP].options[0][1] == 1:
        sendp(Ether(dst=pkt[Ether].src)/IP(src=MY_IP,dst="255.255.255.255")/UDP(sport=67,dport=68)/BOOTP(op=2,yiaddr="10.1.10.251",siaddr=MY_IP,chaddr=pkt[BOOTP].chaddr,xid=pkt[BOOTP].xid)/DHCP(options=[("message-type","offer"),("server_id",MY_IP),("router","10.1.10.254"),("subnet_mask","255.255.255.0"),"end"]),iface=IFACE,verbose=0)
    elif pkt[DHCP].options[0][1] == 3:
        sendp(Ether(dst=pkt[Ether].src)/IP(src=MY_IP,dst="255.255.255.255")/UDP(sport=67,dport=68)/BOOTP(op=2,yiaddr="10.1.10.251",siaddr=MY_IP,chaddr=pkt[BOOTP].chaddr,xid=pkt[BOOTP].xid)/DHCP(options=[("message-type","ack"),("server_id",MY_IP),("router","10.1.10.254"),("subnet_mask","255.255.255.0"),"end"]),iface=IFACE,verbose=0)
sniff(filter="udp and port 67",prn=handle,iface=IFACE,store=0)
