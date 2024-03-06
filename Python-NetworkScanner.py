from ping3 import ping
import ipaddress
import threading
import socket
import getmac
import sys, getopt
import re
from mac_vendor_lookup import MacLookup

# Default max concurrent threads
maxThreads = 1000
# Dictionary to store IP, Mac, and Port information
onlineHosts = {}
# List to store the port information while threading
openPorts = []

def usage():
    print("Scans the local network and prints out IP,MAC,VENDOR,PORTS to the screen\n")
    print("-r Your network with network prefix (ex 192.168.1.0/24)")
    print(f"-t Optionally specifiy the amount of concurrent threads. [Default {maxThreads}]")
    print(f"{sys.argv[0]} -r 192.168.0.1/24")

# Regular expression to match IPv4 address in CIDR notation
def is_network(input_string):
    ip_cidr_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
    # Check if the input string matches the IPv4 or IPv6 CIDR pattern
    if re.match(ip_cidr_pattern, input_string):
        return True
    else:
        print("IPv4 network doesn't match CIDR notation. (ex: 192.168.0.1/24)")
        sys.exit(1)

# Supplying command line arguments
try:
    commandLineArgs = sys.argv[1:]
    unixOptions = "r:ht:"
    opts, args = getopt.getopt(commandLineArgs, unixOptions)
except getopt.GetoptError as e:
    print(f"ERROR: {e}")
    usage()
    sys.exit(2)

for opt, arg in opts:
    if opt == "-h":
        usage()
        sys.exit(0)
    elif opt == "-r":
        subnet = str(arg)
    elif opt == "-t":
        maxThreads = int(arg)

# Exit if the user didn't input mandatory arguments
mandatory_options = ["-r"]
for opt in mandatory_options:
    if not any(opt in o for o in opts):
        print(f"Error: {opt} option missing. Review usage with -h")
        usage()
        sys.exit(2)



# Checks if a device is online and appends it to the onlineHosts list
def ping_device(ip: str):
    ipStr = str(ip)
    try:
        responseTime = ping(ipStr, timeout=1)
        if isinstance(responseTime, float):
            onlineHosts[ipStr] = None
        else:
            pass
    except Exception:
        message = f"Error pinging {ipStr}"
        print(message)

# Grabs the Mac Address from a IP address
def get_mac_address(ip: str) -> str:
    mac = getmac.get_mac_address(ip=ip)
    try:
        vendor = MacLookup().lookup(mac)
    except:
        vendor = "Unknown"

    onlineHosts[ip] = {'MacAddress': mac, 'Vendor': vendor}

# Scans a port to see if its open
def port_scan(ip: str, port: int) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((ip, port))
    if result == 0:
        openPorts.append(str(port))
    else:
        return False


def main(subnet):
    # Ping all hosts on the network using python threads
    network = ipaddress.ip_network(subnet, strict=False)
    threads = []
    # Getting all online hosts
    for ip in network.hosts():
        ipStr = str(ip)
        if len(threads) == maxThreads:
            for thread in threads:
                thread.join()
                threads.clear()

        thread = threading.Thread(target=ping_device, args=(ipStr,))
        thread.start()
        threads.append(thread)

    # Wait for all the threads to clear
    for thread in threads:
        thread.join()
    threads.clear()

    # Getting Device Mac Addresses
    for key in onlineHosts.keys():
        if len(threads) == maxThreads:
            for thread in threads:
                thread.join()
            threads.clear()

        thread = threading.Thread(target=get_mac_address, args=(key,))
        thread.start()
        threads.append(thread)

    # Checking open ports
    for key in onlineHosts.keys():
        for port in range(1,1000):
            if len(threads) == maxThreads:
                for thread in threads:
                    thread.join()
                threads.clear()

            thread = threading.Thread(target=port_scan, args=(key, port))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()
        threads.clear()
        onlineHosts[key].update({'Ports': ' '.join(openPorts)})


is_network(subnet)
main(subnet)

print("IP,MacAddress,Vendor,OpenPorts")
onlineHosts = dict(sorted(onlineHosts.items()))
for key in onlineHosts.keys():
    print(key, onlineHosts[key]['MacAddress'], onlineHosts[key]['Vendor'], onlineHosts[key]['Ports'],sep=",")
