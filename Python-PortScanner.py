from ping3 import ping
import ipaddress
import threading
import socket
import getmac
from mac_vendor_lookup import MacLookup

subnet = ipaddress.ip_network('192.168.50.0/24')

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
    print("Mac code here")
    mac = getmac.get_mac_address(ip="192.168.50.1")
    vendor = MacLookup().lookup(mac)
    onlineHosts[ip] = {'MacAddress': mac, 'Vendor': vendor}
    return mac, vendor


# Ping all hosts on the network using python threads
network = ipaddress.ip_network(subnet, strict=False)
onlineHosts = {}
threads = []
for ip in network.hosts():
    ipStr = str(ip)
    if len(threads) == 16:
        for thread in threads:
            thread.join()
            threads.clear()

    thread = threading.Thread(target=ping_device, args=(ipStr,))
    thread = threading.Thread(target=get_mac_address, args=(ipStr,))
    thread.start()
    threads.append(thread)

# Wait for all the threads to clear
for thread in threads:
    thread.join()
    threads.clear()

for key, value in onlineHosts.items():
    print(key, value)
# onlineHosts = sorted(onlineHosts)
# print(onlineHosts)
