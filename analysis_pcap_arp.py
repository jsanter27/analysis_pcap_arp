# Justin Santer
# Professor Aruna Balasubramanian
# CSE 310 Programming Assignment 3
# April 27, 2020

import dpkt
import sys

# DEFINE CONSTANTS
ARP = 0x0806


class PCAP:
    """Class that encapsulates the relevant data for analysis"""

    def __init__(self):
        self.total_arp = 0

    def increment_arp(self):
        self.total_arp += 1
        return


def main(argc, argv):
    """Driver program"""

    if argc == 1:
        file_path = input("Enter the path of the .pcap file: ")
        print()
    elif argc > 2:
        print("Invalid Arguments: analysis_pcap_arp.py [file path]")
        return
    else:
        file_path = argv[1]

    analysis = analyze_arp(file_path)

    print_analysis(analysis, file_path)

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

        if buffer[12:14] == ARP:
            continue

        analysis.increment_arp()

    return analysis


def print_analysis(analysis, file_path):
    """Prints out .pcap file analysis in digestible format"""

    print("\n")
    print("Analysis of " + file_path + ":\n")
    print("Total ARP Messages in File: " + str(analysis.total_arp))
    print("\n")

    return


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
