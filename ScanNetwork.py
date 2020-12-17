import socket
import nmap
from getmac import get_mac_address
from mac_vendor_lookup import MacLookup
import fcntl
import struct
from colorit import *
import json

found_hosts = []


def exit_program(message):
    sys.exit("\n\n" + message)


# get network ip address like 192.123.456.0
def get_ip_address(interface_name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', bytes(interface_name[:15], 'utf-8'))
    )[20:24])


# perform a network scan with nmap
def scanNetwork(network):
    user_ip = network
    network = network + "/24"
    network_list = []
    global found_hosts
    nm = nmap.PortScanner()
    a = nm.scan(hosts=network, arguments='-sn')

    with open('../scanlog.txt', 'w') as file:
        file.write(json.dumps(json.loads(json.dumps(a)), indent=4))

    for k, v in a['scan'].items():
        if str(v['status']['state']) == 'up':
            ip4 = str(v['addresses']['ipv4'])
            hostname = str(v['hostnames'][0]['name'])
            mac_addr = get_mac_address(ip=ip4)
            if not hostname:
                hostname = "No hostname found"
            if not mac_addr and ip4 == user_ip:
                mac_addr = get_mac_address()
            if mac_addr:
                try:
                    vendor_name = MacLookup().lookup(mac_addr)
                except KeyError:
                    vendor_name = 'No vendor found'
            else:
                mac_addr = 'Your Interface'
                vendor_name = 'Your Interface'
            if ip4 == user_ip:
                vendor_name += "  (Your Interface)"
            network_list.append([ip4, mac_addr, hostname, vendor_name])
            found_hosts.append([ip4, hostname])
    return network_list


# pad the string to specific length
def padString(string, length):
    return string + int(length - len(string)) * " "


def displayInterfaceInfo(interface_name):
    print(color("\n" + "-" * 30, Colors.green))
    print(color("Interface: ", Colors.green) + color(interface_name, Colors.red))
    print(color("IP-Address: ", Colors.green) + color(get_ip_address(interface_name), Colors.red))
    print(color("MAC-Address: ", Colors.green) + color(get_mac_address(interface_name), Colors.red))
    print(color("Vendor: ", Colors.green) + color((MacLookup().lookup(get_mac_address(interface_name))), Colors.red))
    print(color("-" * 30, Colors.green))


# Display the results
def displayNetwork(network):
    for index, ip_info in zip(range(0, len(network)), network):
        ip, mac, host, vendor = ip_info
        if index < 10 and len(network) > 9:
            index = str(0) + str(index)
        index = str(index)
        ip = padString(ip, 19)
        mac = padString(mac, 22)
        host = padString(host, 26)
        print(
            color("[" + str(index) + "] ", Colors.green) + color(ip, Colors.red) + color(mac, Colors.blue) + color(host,
                                                                                                                   Colors.purple) + color(
                vendor, Colors.orange))


def chooseInterface():
    interfaces = socket.if_nameindex()
    interface_list = []

    for interface in interfaces:
        try:
            if interface[1] != 'lo':
                get_ip_address(interface[1])
                interface_list.append(interface[1])
        except:
            pass
    for index, cleared_interface in zip(range(0, len(interface_list)), interface_list):
        try:
            get_ip_address(cleared_interface)
            if cleared_interface != 'lo':
                print(color("[" + str(index) + "]", Colors.green) + " " + color(cleared_interface,
                                                                                Colors.red) + " " + color(
                    get_ip_address(cleared_interface), Colors.green))

        except OSError:
            pass

    can_break = False

    if interface_list:
        while not can_break:
            choice = input(color("\nSelect the ID of the interface: ", Colors.red))
            if choice.lower() == "e":
                exit_program("See you!")
            try:
                choice = interface_list[int(choice)]
                return choice
            except:
                pass
    else:
        return None


def updateInterfaceInfo(interface_update):
    while True:
        scanned_network = scanNetwork(get_ip_address(interface_update))
        os.system('cls' if os.name == 'nt' else "clear")
        displayInterfaceInfo(interface_update)
        print("\n" * 3)
        displayNetwork(scanned_network)


if __name__ == '__main__':
    init_colorit()
    try:
        interface = chooseInterface()

        if interface is None:
            print("Found no interfaces, are you online?")
            exit_program("Found no interfaces, are you online?")
        os.system('cls' if os.name == 'nt' else "clear")
        updateInterfaceInfo(interface)
        print("Finished Scan")

    except KeyboardInterrupt:
        exit_program("See you!")
