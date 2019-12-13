""" pypacket - parse packets so a human can use them """

import socket
import ipaddress
from struct import unpack

class Packet():
    """Packet class - Parses an Ethernet frame so you dont have to!@#"""
    # pylint: disable=too-many-instance-attributes
    def __init__(self, raw_packet): # pylint: disable=R0915
        self.packet = raw_packet # Raw packet contents
        self.data = None         # Packet data
        self.ethertype = None    # Ethertype.
        self.protocol = None     # Protocol: TCP, UDP, ICMP, ARP, IGMP, ...
        self.saddr = None        # Source IP
        self.daddr = None        # Destination IP
        self.shwaddr = None      # Source MAC
        self.dhwaddr = None      # Destination MAC
        self.sport = None        # Source port
        self.dport = None        # Destination port
        self.ttl = None          # Time to Live
        self.seq = None          # Sequence number
        self.ack = None          # Acknowledgement number
        self.window = None       # TCP window
        self.tcpflags = None     # TCP flags
        self.tcpheaderlen = None # TCP header length
        self.length = None       # Length
        self.checksum = None     # Checksum
        self.icmptype = None     # ICMP type
        self.icmpcode = None     # ICMP code
        self.dot1q_offset = 0    # Offset for 802.1q header

        # Constants
        self.ethernet_header_length = 14
        self.ip_header_length = 20
        self.ipv6_header_length = 40
        self.tcp_header_length = 20
        self.udp_header_length = 8
        self.icmp_header_length = 4
        self.dot1q_header_length = 4

        # Parse Ethernet header
        self.ethernet_header = \
            unpack("!6s6sH", raw_packet[:self.ethernet_header_length])

        self.dhwaddr = self.mac_address(self.ethernet_header[0])
        self.shwaddr = self.mac_address(self.ethernet_header[1])
        self.ethertype = self.ethernet_header[2]

        # Check Ethertype and parse accordingly
        if self.ethertype == 0x0800 or self.ethertype == 0x8100: # IP
            # Check for 802.1q
            if self.ethertype == 0x8100:
                self.dot1q_offset = 4
            self.parse_ip_header()

            if self.protocol == 6:
                self.parse_tcp_header()
            elif self.protocol == 17:
                self.parse_udp_header()
            elif self.protocol == 1:
                self.parse_icmp_header()
            elif self.protocol == 2:
                self.parse_igmp_header()
            elif self.protocol == 89:
                self.parse_ospf_header()
            elif self.protocol == 103:
                self.parse_pim_header()
            else: # UNKNOWN PROTOCOL
                # TODO shouldn't print() this...
                print(self.protocol, self.packet)

        elif self.ethertype == 0x86dd: # IPv6
            self.parse_ipv6_header()

        elif self.ethertype == 0x0806: # ARP
            self.parse_arp()

    def parse_arp(self):
        """Packet.parse_arp() - Parse ARP packets."""
        # TODO: finish this
        self.protocol = "ARP"

    def parse_ospf_header(self):
        """Packet.parse_ospf_header() - Parse OSPF headers."""
        # TODO finish this
        self.protocol = "OSPF"

    def parse_pim_header(self):
        """Packet.parse_pim_header() - Parse PIM headers."""
        # TODO finish this
        self.protocol = "PIM"

    def parse_ipv6_header(self):
        """Packet.parse_ipv6_header() - Parse IPv6 packets."""
        # TODO: finish this
        self.protocol = "IPv6"
        offset = self.ethernet_header_length
        ipv6_header = unpack("!LHBB16s16s",
                             self.packet[offset:offset+self.ipv6_header_length])
        self.length = ipv6_header[1]
        self.hoplimit = ipv6_header[3]
        self.saddr = str(ipaddress.IPv6Address(ipv6_header[4]))
        self.daddr = str(ipaddress.IPv6Address(ipv6_header[5]))
        if ipv6_header[2] == 6:
            self.parse_tcp_header()
        elif ipv6_header[2] == 17:
            self.parse_udp_header()
        elif ipv6_header[2] == 58: # ICMPv6
            self.parse_icmp_header()

    def parse_igmp_header(self):
        """Packet.parse_igmp_header() - Parse IGMP header."""
        # TODO: finish this
        self.protocol = "IGMP"

    def parse_icmp_header(self):
        """Packet.parse_icmp_header() - Parse ICMP header."""
        self.protocol = "ICMP6" if self.protocol == "IPv6" else "ICMP"
        offset = self.dot1q_offset + self.ethernet_header_length
        if self.protocol == "ICMP":
            offset += self.ip_header_length
        elif self.protocol == "ICMP6":
            offset += self.ipv6_header_length
        icmp_header = unpack("!BBH",
                             self.packet[offset:offset+self.icmp_header_length])
        self.icmptype = icmp_header[0]
        self.icmpcode = icmp_header[1]
        self.checksum = icmp_header[2]
        self.data = self.packet[offset + self.icmp_header_length:]

    def parse_udp_header(self):
        """Packet.parse_udp_header() - Parse UDP header."""
        self.protocol = "UDP6" if self.protocol == "IPv6" else "UDP"
        offset = self.dot1q_offset + self.ethernet_header_length
        if self.protocol == "UDP":
            offset += self.ip_header_length
        elif self.protocol == "UDP6":
            offset += self.ipv6_header_length
        udp_header = unpack("!HHHH",
                            self.packet[offset:offset + self.udp_header_length])
        self.sport = udp_header[0]
        self.dport = udp_header[1]
        self.length = udp_header[2]
        self.checksum = udp_header[3]
        self.data = self.packet[offset + self.udp_header_length:]

    def parse_tcp_header(self):
        """Packet.parse_tcp_header() - Parse TCP header."""
        self.protocol = "TCP6" if self.protocol == "IPv6" else "TCP"
        offset = self.dot1q_offset + self.ethernet_header_length
        if self.protocol == "TCP":
            offset += self.ip_header_length
        elif self.protocol == "TCP6":
            offset += self.ipv6_header_length
        tcp_header = unpack("!HHLLBBHHH",
                            self.packet[offset:offset + self.tcp_header_length])
        self.sport = tcp_header[0]
        self.dport = tcp_header[1]
        self.seq = tcp_header[2]
        self.ack = tcp_header[3]
        self.tcpheaderlen = ((tcp_header[4] >> 4) & 0xff) * 4
        self.tcpflags = self.parse_tcp_flags(tcp_header[5])
        self.window = tcp_header[6]
        self.checksum = tcp_header[7]
        self.data = self.packet[offset+self.tcpheaderlen:]

    @staticmethod
    def parse_tcp_flags(control):
        """parse_tcp_flags() - Determine which TCP flags are set.

        Args:
            control (str) - TCP control bytes

        Returns:
            tcpdump-style flags (str).
        """
        tcp_flags = ""
        if control & 0x01: # FIN
            tcp_flags += "F"
        if control & 0x02: # SYN
            tcp_flags += "S"
        if control & 0x04: # RST
            tcp_flags += "R"
        if control & 0x08: # PSH
            tcp_flags += "P"
        if control & 0x10: # ACK
            tcp_flags += "A"
        if control & 0x20: # URG
            tcp_flags += "U"
        if control & 0x40: # ECE
            tcp_flags += "E"
        if control & 0x80: # CWR
            tcp_flags += "C"
        return tcp_flags

    def parse_ip_header(self):
        """Packet.parse_ip_header() - Parse IP header."""
        # TODO: make this complete. May need some of the other header elements
        #       for other tools instead of ttl, protocol, source, and
        #       destination: http://www.networksorcery.com/enp/protocol/ip.htm
        start = self.dot1q_offset + self.ethernet_header_length
        end = self.dot1q_offset + self.ethernet_header_length + self.ip_header_length
        ip_header = unpack("!BBHHHBBH4s4s", self.packet[start:end])

        self.ttl = ip_header[5]
        self.protocol = ip_header[6]
        self.saddr = socket.inet_ntoa(ip_header[8])
        self.daddr = socket.inet_ntoa(ip_header[9])

    @staticmethod
    def mac_address(address):
        """mac_address() - Convert 6 bytes to human-readable MAC address.

        Args:
            address - MAC address bytes.

        Returns:
            Human-readable MAC address (str). Ex: '00:11:22:33:44:55'
        """
        result = ""
        if len(address) != 6:
            return None
        for byte in address:
            result += "%.2x:" % byte
        return result[:-1] # Strip trailing colon
