#!/usr/bin/env python3

import json
from base64 import b64encode
from time import sleep
from datetime import datetime

import dnslib
from dmfrbloom.timefilter import TimeFilter

import pcapy

from pypacket import Packet


# https://en.wikipedia.org/wiki/List_of_DNS_record_types
DNS_RECORD_TYPES = {
    1: "A",
    28: "AAAA",
    18: "AFSDB",
    42: "APL",
    257: "CAA",
    60: "CDNSKEY",
    59: "CDS",
    37: "CERT",
    5: "CNAME",
    62: "CSYNC",
    49: "DHCID",
    32769: "DLV",
    39: "DNAME",
    48: "DNSKEY",
    43: "DS",
    55: "HIP",
    45: "IPSECKEY",
    25: "KEY",
    36: "KX",
    29: "LOC",
    15: "MX",
    35: "NAPTR",
    2: "NS",
    47: "NSEC",
    50: "NSEC3",
    51: "NSEC3PARAM",
    61: "OPENPGPKEY",
    12: "PTR",
    46: "RRSIG",
    17: "RP",
    24: "SIG",
    53: "SMIMEA",
    6: "SOA",
    33: "SRV",
    44: "SSHFP",
    32768: "TA",
    249: "TKEY",
    52: "TLSA",
    250: "TSIG",
    16: "TXT",
    256: "URI",

    255: "*",
    252: "AXFR",
    251: "IXFR",
    41: "OPT",

    # Obsolete record types
    3: "MD",
    4: "MF",
    254: "MAILA",
    7: "MB",
    8: "MG",
    9: "MR",
    14: "MINFO",
    253: "MAILB",
    11: "WKS",
    #32: "NB", # now assigned to NIMLOC
    #33: "NBTSTAT", # now assigned to  SRV
    10: "NULL",
    38: "A6",
    13: "HINFO",
    19: "X25",
    20: "ISDN",
    21: "RT",
    22: "NSAP",
    23: "NSAP-PTR",
    26: "PX",
    31: "EID",
    32: "NIMLOC", # duplicate id: NB
    34: "ATMA",
    40: "SINK",
    27: "GPOS",
    100: "UINFO",
    101: "UID",
    102: "GID",
    103: "UNSPEC",
    99: "SPF",
    56: "NINFO",
    57: "RKEY",
    58: "TALINK",
    104: "NID",
    105: "L32",
    106: "L64",
    107: "LP",
    108: "EUI48",
    109: "EUI64",
    259: "DOA",
}

class Sniffer():
    def __init__(self, interface, promisc=1, bpf="", snaplen=65535, timeout=100):
        self.interface = interface
        self.promisc = promisc
        self.bpf = bpf
        self.snaplen = snaplen
        self.timeout = timeout
        self.sniffer = None

    def start(self):
        self.sniffer = pcapy.open_live(self.interface,
                                       self.snaplen,
                                       self.promisc,
                                       self.timeout)
        self.sniffer.setfilter(self.bpf)

    def next(self):
        _, packet = self.sniffer.next()
        return Packet(packet) if packet else None

    def setnonblock(self):
        # TODO error check
        self.sniffer.setnonblock(1)


def main():
    time_filter = TimeFilter(100000, 0.001, 60*60*24)

    capture = Sniffer("eth0", bpf="port 53 or port 5353")
    capture.start()
    capture.setnonblock()

    while True:
        packet = capture.next()
        if not packet:
            # This avoids 100% CPU use. Probably a better way to do this??
            sleep(0.05)
            continue

        output = {}

        output["timestamp"] = datetime.now().replace(microsecond=0).isoformat()
        output["protocol"] = packet.protocol
        output["saddr"] = packet.saddr
        output["daddr"] = packet.daddr
        output["sport"] = packet.sport
        output["dport"] = packet.dport

        try:
            dns_packet = dnslib.DNSRecord.parse(packet.data)
        except (dnslib.dns.DNSError, TypeError):
            # TODO this is probably not DNS data. should be an alert!
            if packet.data:
                output["payload"] = b64encode(packet.data).decode("utf-8")
            print(json.dumps(output))
            continue

        output["id"] = dns_packet.header.id
        output["q"] = dns_packet.header.q
        output["a"] = dns_packet.header.a

        if dns_packet.questions:
            output["questions"] = []
            for question in dns_packet.questions:
                output["questions"].append({"qname": str(question.qname),
                                            "qtype": DNS_RECORD_TYPES[question.qtype],
                                            "qtype_id": question.qtype,
                                            "qclass": question.qclass})

        if dns_packet.rr:
            output["rr"] = []
            for rr in dns_packet.rr:
                output["rr"].append({"rname": str(rr.rname),
                                     "rtype": DNS_RECORD_TYPES[rr.rtype],
                                     "rtype_id": rr.rtype,
                                     "rclass": rr.rclass,
                                     "rdata": str(rr.rdata),
                                     "ttl": rr.ttl})

        if dns_packet.auth:
            output["auth"] = []
            for auth in dns_packet.auth:
                output["auth"].append({"rname": str(auth.rname),
                                       "rtype": DNS_RECORD_TYPES[auth.rtype],
                                       "rtype_id": auth.rtype,
                                       "rclass": auth.rclass,
                                       "rdata": str(auth.rdata),
                                       "ttl": auth.ttl})

        if dns_packet.ar:
            output["ar"] = []
            for ar in dns_packet.ar:
                output["ar"].append({"rname": str(ar.rname),
                                     "rtype": DNS_RECORD_TYPES[ar.rtype],
                                     "rtype_id": ar.rtype,
                                     "rclass": ar.rclass,
                                     "rdata": str(ar.rdata),
                                     "ttl": ar.ttl})

        # TODO log this for SIEM
        print(json.dumps(output))

        # Remove volatile fields before adding to bloom filter
        output.pop("timestamp")
        output.pop("sport")
        output.pop("dport")
        output.pop("id")
        json_output = json.dumps(output)

        # Alert if not in the filter, otherwise update timestamps.
        if time_filter.lookup(json_output) is False:
            # TODO alert if baseline is complete
            print("Not in filter:", json.dumps(output, indent=4))
        time_filter.add(json_output)

        # This will print a dig-like output of the dns query
        # print(dns_packet)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
