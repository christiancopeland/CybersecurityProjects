# basic_keylogger.py usage
```
python3 basic_keylogger.py
```
 - When ran, there will be a .logged folder created in the current user's home directory. While running, a file will be appended with a timestamp alongside every key stroked.


# nmap_scan.py usage
```
python3 nmap_scan.py -t 127.0.0.1 -o scan.txt -s (all, os, services)
```
 - This script takes 3 arguments. -t provides the target IP address, -o enables logging and requires a filename to write to, and -s allows the user to decide between running nmap OS Detection scripts, Service Scanning scripts, or both 


# analyze_pcap.py usage
```
python3 analyze_pcap.py --interface eno1 --capture live --packet-count 100
```
 - This script is a work in progress as I plan to take this a bit further than the previous two scripts. Currently, you can capture and output packets in two modes: LiveCapture and FileCapture. If you run in live mode, I recommend specifying a --packet-count value so that you don't get left with an infinite wall of packets... unless you want that, in which case, TA DAAAAAA. 
 - The goal is to have a report output to a file with some analysis done for you. I plan to analyze ports, source and destination IPs, and protocols. The report in my head so far will list the top 10 protocols, IP addresses, and ports by packet count. For now, this seems like it will mostly be useful as a toy to see a prettier version of packets, but I hope to add more useful analysis to this script like analysing TCP flags and packet timing. 

 # scapy_pkt_sniff.py
 ```
 don't
 ```
 - This script is not useful right now. It can capture and display some traffic, but requires some work before worth running yourself. 