from ping3 import ping
import ipaddress
import threading
import socket
import getmac
from mac_vendor_lookup import MacLookup

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
    mac = getmac.get_mac_address(ip=ip)
    vendor = MacLookup().lookup(mac)
    onlineHosts[ip] = {'MacAddress': mac, 'Vendor': vendor}
    return mac, vendor

def main(subnet):
    # Ping all hosts on the network using python threads
    network = ipaddress.ip_network(subnet, strict=False)
    threads = []
    # Getting all online hosts
    print("Getting online hosts")
    for ip in network.hosts():
        ipStr = str(ip)
        print(ipStr)
        if len(threads) == 25:
            for thread in threads:
                thread.join()
                threads.clear()

        thread = threading.Thread(target=ping_device, args=(ipStr,))
        # thread = threading.Thread(target=get_mac_address, args=(ipStr,))
        thread.start()
        threads.append(thread)

    # Wait for all the threads to clear
    for thread in threads:
        thread.join()
    threads.clear()

    # Getting Device Mac Addresses
    for key in onlineHosts.keys():
        mac, vendor = get_mac_address(key)
        onlineHosts[key] = {'MacAddress': mac, 'Vendor': vendor}

subnet = ipaddress.ip_network('192.168.50.0/24')
onlineHosts = {}
main(subnet)

print(onlineHosts.items())
