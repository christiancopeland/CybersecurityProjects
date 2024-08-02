import nmap3
import json
import argparse




def get_args():
    parser = argparse.ArgumentParser() 
    parser.add_argument("-t", "--target", dest="target", help="Specify target url you want to scan")
    parser.add_argument("-o", "--output", dest="output", help="Save results to file")
    parser.add_argument("-s", "--scan-type", dest="scan_type", help="Specify type of scan to perform (os, services, or all)")
    args = parser.parse_args()
    return args

def check_os(target):
    try:
        os_results = nmap.nmap_os_detection(target)
        return os_results
    except Exception as e:
        print(f"Error: {e}")
        return None

# like saying 'nmap -sV target'
def get_services(target):
    try:
        weak_scan_services = nmap.nmap_version_detection(target)
        return weak_scan_services
    except Exception as e:
        print(f"Error: {e}")
        return None

def print_json(blob, indent=0, output_str=""):
    for key, value in blob.items():
        if isinstance(value, dict):
            output_str += '  ' * indent + key + ':\n'
            output_str = print_json(value, indent + 1, output_str)
        elif isinstance(value, list):
            output_str += '  ' * indent + key + ':\n'
            for item in value:
                output_str = print_json(item, indent + 1, output_str)
        else:
            output_str += '  ' * indent + key + ': ' + str(value) + '\n'
    return output_str


# could be nice to tabulate received data for those who don't like print_json

# def print_table(data, headers):
#     print(tabulate(data, headers, tablefmt="grid"))


def main():
    args = get_args()
    target = args.target
    scan_type = args.scan_type

    if scan_type == "os" or scan_type == "all":
        os_results = check_os(target)
        if os_results:
            os_output = print_json(os_results)
            print("\n==== OS Detection Results for " + target + " ==== \n\n")
            print(os_output)
            print("\n\n==== End of OS Detection Results for " + target + " ====\n\n")
    
    if scan_type == "services" or scan_type == "all":
        services_results = get_services(target)
        if services_results:
            services_output = print_json(services_results)
            print("\n==== Service Scan Results for " + target + " ==== \n\n")
            print(services_output)
            print("\n\n==== End of Service Scan Results for " + target + " ====\n\n")
     # just like saying 'nmap -oA outputFile'       
    if args.output:
        with open(args.output, "w") as f:
            if os_results:
                f.write("==== OS Detection Results for " + target + " ====\n\n")
                f.write(os_output)
                f.write("\n\n==== End of OS Detection Results for " + target + " ====\n\n")
            if services_results:
                f.write("\n==== Service Scan Results for " + target + " ==== \n\n")
                f.write(services_output)
                f.write("\n\n==== End of Service Scan Results for " + target + " ====\n\n")


if __name__ == '__main__':
    nmap = nmap3.Nmap()
    main()
   