from ping3 import ping
import ipaddress
import threading
import socket
import getmac
import sys, getopt
from mac_vendor_lookup import MacLookup

def usage():
    print("Scans the local network and prints out IP,MAC,VENDOR,PORTS to the screen")
    print(f"{sys.argv[0]} -r 192.168.0.1/24")

try:
    commandLineArgs = sys.argv[1:]
    unixOptions = "r:h"
    opts, args = getopt.getopt(commandLineArgs, unixOptions)
except getopt.GetoptError as e:
    print(f"ERROR: {e}")
    usage()
    sys.exit(2)

# Create new variables to store the users args
for opt, arg in opts:
    if opt == "-h":
        usage()
        sys.exit(0)
    elif opt == "-r":
        subnet = str(arg)

# Exit if the user didn't input all arguments
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

onlineHosts = {}
openPorts = []
maxThreads = 1000

main(subnet)

print("IP,MacAddress,Vendor,OpenPorts")
for key in onlineHosts.keys():
    print(key, onlineHosts[key]['MacAddress'], onlineHosts[key]['Vendor'], onlineHosts[key]['Ports'],sep=",")
