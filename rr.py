# cquade/Desktop/proj/rr.py
# ROUTER REAPER
# A network scanning tool powered by Scapy
# Created by Colin Quade and Riley Westerman
# CPSC 4240

from scapy.all import sniff, ARP
from colorama import Fore

# Function that gets the 
def log_ip(ip_address):
    with open("malicious_ips.txt", "a") as file:
        file.write("Suspicious IP: " + ip_address + "\n")
    print(Fore.RED + f"Logged malicious IP: {ip_address}")

# Define a function to handle each packet sniffed
def handle_packet(packet):
    try:
        # Print the packet summary
        print(Fore.GREEN + packet.summary())
        
        # Check for large packet (Change 1500 to your threshold value)
        if len(packet) > 1500:
            print(Fore.YELLOW + "\n================================")
            print(Fore.YELLOW + "Warning: Large packet detected!")
            print(Fore.YELLOW + "================================\n")

        # Check for ARP spoofing
        if packet.haslayer(ARP):
            if packet[ARP].op == 2:  # ARP response (op=2)
                # Library for IP-MAC Pairs; for the sake of the demo these are fake
                # In future iterations, fill the library with real IP-MAC pairs
                legitimate_arp_pairs = {
                    "192.168.1.1": "00:1A:2B:3C:4D:5E",
                    "192.168.1.2": "6A:B5:C4:D3:E2:F1",
                    "192.168.1.3": "AA:BB:CC:DD:EE:FF",
                    "192.168.1.4": "12:34:56:78:9A:BC",
                    "192.168.1.5": "98:76:54:32:10:FE",
                    "192.168.1.6": "F0:E1:D2:C3:B4:A5"
                }
                sender_ip = packet[ARP].psrc
                sender_mac = packet[ARP].hwsrc
                if sender_ip in legitimate_arp_pairs:
                    if legitimate_arp_pairs[sender_ip] != sender_mac:
                        print(Fore.RED + "\n====================================================================================================================")
                        print(Fore.RED + f"Warning: ARP Spoofing Detected!!! {sender_ip} is associated with {sender_mac} instead of {legitimate_arp_pairs[sender_ip]}")
                        log_ip(sender_ip)
                        print(Fore.RED + "====================================================================================================================\n")
    except Exception as e:
        print(f"Error processing packet: {e}")

def print_logo():
    print(Fore.RED + """\n\n\n  .S_sSSs      sSSs_sSSs     .S       S.   sdSS_SSSSSSbs    sSSs   .S_sSSs           .S_sSSs      sSSs   .S_SSSs     .S_sSSs      sSSs   .S_sSSs    
.SS~YS%%b    d%%SP~YS%%b   .SS       SS.  YSSS~S%SSSSSP   d%%SP  .SS~YS%%b         .SS~YS%%b    d%%SP  .SS~SSSSS   .SS~YS%%b    d%%SP  .SS~YS%%b   
S%S   `S%b  d%S'     `S%b  S%S       S%S       S%S       d%S'    S%S   `S%b        S%S   `S%b  d%S'    S%S   SSSS  S%S   `S%b  d%S'    S%S   `S%b  
S%S    S%S  S%S       S%S  S%S       S%S       S%S       S%S     S%S    S%S        S%S    S%S  S%S     S%S    S%S  S%S    S%S  S%S     S%S    S%S  
S%S    d*S  S&S       S&S  S&S       S&S       S&S       S&S     S%S    d*S        S%S    d*S  S&S     S%S SSSS%S  S%S    d*S  S&S     S%S    d*S  
S&S   .S*S  S&S       S&S  S&S       S&S       S&S       S&S_Ss  S&S   .S*S        S&S   .S*S  S&S_Ss  S&S  SSS%S  S&S   .S*S  S&S_Ss  S&S   .S*S  
S&S_sdSSS   S&S       S&S  S&S       S&S       S&S       S&S~SP  S&S_sdSSS         S&S_sdSSS   S&S~SP  S&S    S&S  S&S_sdSSS   S&S~SP  S&S_sdSSS   
S&S~YSY%b   S&S       S&S  S&S       S&S       S&S       S&S     S&S~YSY%b         S&S~YSY%b   S&S     S&S    S&S  S&S~YSSY    S&S     S&S~YSY%b   
S*S   `S%b  S*b       d*S  S*b       d*S       S*S       S*b     S*S   `S%b        S*S   `S%b  S*b     S*S    S&S  S*S         S*b     S*S   `S%b  
S*S    S%S  S*S.     .S*S  S*S.     .S*S       S*S       S*S.    S*S    S%S        S*S    S%S  S*S.    S*S    S*S  S*S         S*S.    S*S    S%S  
S*S    S&S   SSSbs_sdSSS    SSSbs_sdSSS        S*S        SSSbs  S*S    S&S        S*S    S&S   SSSbs  S*S    S*S  S*S          SSSbs  S*S    S&S  
S*S    SSS    YSSP~YSSY      YSSP~YSSY         S*S         YSSP  S*S    SSS        S*S    SSS    YSSP  SSS    S*S  S*S           YSSP  S*S    SSS  
SP                                             SP                SP                SP                         SP   SP                  SP          
Y                                              Y                 Y                 Y                          Y    Y                   Y           
                                                                                                                                                   
 """)

def main():
    print_logo()
    print(Fore.CYAN + "Analyze packets with this simple program!\n")
    print(Fore.CYAN + "Press 's' and then 'Enter' to start sniffing packets. Use Ctrl+C to exit.")
    start_sniffing = input()
    if start_sniffing.lower() == 's':
        print(Fore.CYAN + "Starting packet sniffing...")
        # Start sniffing packets
        sniff(prn=handle_packet)
    else:
        print("Exiting program.")


if __name__ == "__main__":
    main()