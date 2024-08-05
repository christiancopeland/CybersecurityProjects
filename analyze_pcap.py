import pyshark
import os
import argparse

# TODO: Output analysis to elastic/json for pipelines and elastic stacks (SIEMS)

def get_args():
    parser = argparse.ArgumentParser() 
    parser.add_argument("-pp", "--pcap-path", dest="pcapPath", help="Specify path to pcap file to analyse")
    parser.add_argument("-f", "--filter", dest="filter", help="Specify a Wireshark display filter (http, dns, )")
    parser.add_argument("-c", "--capture", dest="captureMode", help="Specify a Pyshark capture type (live, inmem, or file)")
    parser.add_argument("-i", "--interface", dest="interface", help="Specify an interface or ip address to sniff packets from (live, inmem, or file)")
    parser.add_argument("-pC", "--", dest="packetCount", help="Specify an integer amount of packets to capture when using Live Capture (1, 10, 100, etc)")
    args = parser.parse_args()
    return args

# if captureMode is live, sniff on specified interface for length of specified packetCount. If no specified packetCount, sniff continuously
def live_capture(interface, numPacketsToSniff):
    capture = pyshark.LiveCapture(interface=interface)
    if numPacketsToSniff:
        for packet in capture.sniff_continuously(numPacketsToSniff):    
            print(packet)
    else:
        for packet in capture.sniff_continuously():
            print(packet)

def file_capture(pcapPath):
    try:
        capture = pyshark.FileCapture(pcapPath)
        for packet in capture:
            print(packet)
    except Exception as e:
        print(f"Error: {e}")


def main():
    args = get_args()
    captureMode = args.captureMode
    pcapPath = args.pcapPath
    packetFilter = args.filter
    interface = args.interface
    numPacketsToSniff = args.packetCount

    if captureMode == "live":
        live_capture(interface, numPacketsToSniff)
    elif captureMode == "file":
        file_capture(pcapPath)

    pass

if __name__ == '__main__':
    main()
    

    # homeDir = os.path.expanduser('~')
    # logDir = os.path.join(homeDir, 'pcap-practice')
    

   
    