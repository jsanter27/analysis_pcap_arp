# Justin Santer
# Professor Aruna Balasubramanian
# CSE 310 Programming Assignment 3
# April 27, 2020

import dpkt
import sys

# DEFINE CONSTANTS
ARP = "0806"
REQUEST = "0001"
REPLY = "0002"
ETHERNET = "0001"
IPV4 = "0800"


class PCAP:
    """Class that encapsulates the relevant data for analysis"""

    def __init__(self):
        self.total_arp = 0
        self.exchange = None
        self.request_table = {}
        self.request = None
        self.reply = None

    def increment_arp(self):
        """Increments the total ARP message count by 1"""
        self.total_arp += 1
        return

    def add_request(self, request):
        """Adds ARP request to dictionary"""
        self.request_table[request.sender_ip] = request
        return

    def get_request(self, reply):
        """Takes the ARP reply's target IP and returns the corresponding ARP request"""
        return self.request_table.get(reply.target_ip, None)

    def __str__(self):
        string = "\n\n"
        string += "***********************************************************\n\n"
        string += "Total ARP Messages in File: " + str(self.total_arp) + "\n\n\n"
        string += str(self.request) + "\n"
        string += str(self.reply) + "\n"
        string += "***********************************************************\n"
        return string


class ARPMessage:
    """ARP Header Information"""

    def __init__(self, hardware_type=None, protocol_type=None, hardware_size=None, protocol_size=None,
                 arp_type=None, sender_mac=None, sender_ip=None, target_mac=None, target_ip=None):
        self.hardware_type = hardware_type
        self.protocol_type = protocol_type
        self.hardware_size = hardware_size
        self.protocol_size = protocol_size
        self.arp_type = arp_type
        self.sender_mac = sender_mac
        self.sender_ip = sender_ip
        self.target_mac = target_mac
        self.target_ip = target_ip

    def __str__(self):
        string = "ARP " + self.arp_type + " PACKET\n"
        string += "   Hardware Type: 0x" + self.hardware_type + "\n"
        string += "   Protocol Type: 0x" + self.protocol_type + "\n"
        string += "   Hardware Size: " + self.hardware_size + "\n"
        string += "   Protocol Size: " + self.protocol_size + "\n"
        string += "   Sender MAC address: " + self.sender_mac + "\n"
        string += "   Sender IP  address: " + self.sender_ip + "\n"
        string += "   Target MAC address: " + self.target_mac + "\n"
        string += "   Target IP  address: " + self.target_ip + "\n"
        return string


def main(argc, argv):
    """Driver program"""

    if argc == 1:
        file_path = input("\nEnter the path of the .pcap file: ")
        print()
    elif argc > 2:
        print("Invalid Arguments: analysis_pcap_arp.py [file path]")
        return
    else:
        file_path = argv[1]

    analysis = analyze_arp(file_path)

    print(str(analysis))

    return


def analyze_arp(file_path):
    """Performs ARP analysis on given PCAP file"""

    # ATTEMPT TO OPEN FILE
    try:
        file = open(file_path, 'rb')
    except FileNotFoundError:
        print("File Not Found")
        return

    pcap = dpkt.pcap.Reader(file)
    analysis = PCAP()

    # LOOP THROUGH THE PACKETS IN THE FILE
    for timestamp, buffer in pcap:

        # IF PACKET ISN'T ARP, SKIP IT
        if not is_arp(buffer):
            continue

        # ADD ONE TO THE TOTAL ARP MESSAGE COUNT
        analysis.increment_arp()

        # GET HEADER INFORMATION USING HELPER FUNCTIONS
        hardware_type = get_hardware_type(buffer)
        protocol_type = get_protocol_type(buffer)
        hardware_size = get_hardware_size(buffer)
        protocol_size = get_protocol_size(buffer)
        arp_type = get_arp_type(buffer)
        sender_mac = get_sender_mac(buffer)
        sender_ip = get_sender_ip(buffer)
        target_mac = get_target_mac(buffer)
        target_ip = get_target_ip(buffer)

        # CREATE ARP MESSAGE OBJECT
        message = ARPMessage(hardware_type, protocol_type, hardware_size, protocol_size, arp_type, sender_mac,
                             sender_ip, target_mac, target_ip)

        # print(message)

        if message.arp_type == "REQUEST":
            analysis.add_request(message)
        elif message.arp_type == "REPLY":
            request = analysis.get_request(message)
            analysis.request = request
            analysis.reply = message

    return analysis


def is_arp(buffer):
    """Returns True if Packet is ARP, False if otherwise"""

    if buffer[12:14].hex() == ARP:
        return True
    else:
        return False


def get_hardware_type(buffer):
    """Returns String interpretation of the Packet's hardware type"""

    hardware_type = buffer[14:16].hex()

    if hardware_type == ETHERNET:
        return hardware_type + " (Ethernet)"
    else:
        return hardware_type


def get_protocol_type(buffer):
    """Returns String interpretation of the Packet's protocol type"""

    protocol_type = buffer[16:18].hex()

    if protocol_type == IPV4:
        return protocol_type + " (IPv4)"
    else:
        return protocol_type


def get_hardware_size(buffer):
    """Returns String value of the Packet's hardware size"""

    return str(int(buffer[18]))


def get_protocol_size(buffer):
    """Returns String value of the Packet's protocol size"""

    return str(int(buffer[19]))


def get_arp_type(buffer):
    """Returns String interpretation of the Packet's ARP type (ex. Request, Reply, ...)"""

    arp_type = buffer[20:22].hex()

    if arp_type == REPLY:
        return "REPLY"
    elif arp_type == REQUEST:
        return "REQUEST"
    else:
        return "OTHER"


def get_sender_mac(buffer):
    """Returns String interpretation of the Packet's Sender MAC address"""

    sender_mac = bytes_to_mac(buffer[22:28])

    return sender_mac


def get_sender_ip(buffer):
    """Returns String interpretation of the Packet's Sender IP address"""

    sender_ip = bytes_to_ip(buffer[28:32])

    return sender_ip


def get_target_mac(buffer):
    """Returns String interpretation of the Packet's Target MAC address"""

    target_mac = bytes_to_mac(buffer[32:38])

    return target_mac


def get_target_ip(buffer):
    """Returns String interpretation of the Packet's Target IP address"""

    target_ip = bytes_to_ip(buffer[38:42])

    return target_ip


def bytes_to_mac(byte_array):
    """Converts bytes to String interpretation of MAC address"""

    if len(byte_array) != 6:
        return None

    mac = byte_array.hex()
    return mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" + mac[10:]


def bytes_to_ip(byte_array):
    """Converts bytes to String interpretation of IP address"""

    if len(byte_array) != 4:
        return None

    return str(int(byte_array[0])) + "." + str(int(byte_array[1])) + "." + str(int(byte_array[2])) + "." + \
        str(int(byte_array[3]))


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
