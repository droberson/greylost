#!/usr/bin/env python3

""" greylost - DNS threat hunting
"""

import json
import copy
from base64 import b64encode
from time import sleep
from datetime import datetime

import dnslib
from dmfrbloom.timefilter import TimeFilter

from pysniffer import Sniffer
from record_types import DNS_RECORD_TYPES


def _parse_dns_response(response_list):
    """ _parse_dns_response() - Parses DNS responses.

    Args:
        response_list (list) - Response list

    Returns:
        List of responses sorted by "rdata" key.
    """
    response_sorted_list = []
    for response in response_list:
        response_sorted_list.append({"rname": str(response.rname),
                                     "rtype": DNS_RECORD_TYPES[response.rtype],
                                     "rtype_id": response.rtype,
                                     "rclass": response.rclass,
                                     "rdata": str(response.rdata),
                                     "ttl": response.ttl})
    return sorted(response_sorted_list, key=lambda k: k["rdata"])


def _parse_dns_packet(packet):
    """ _parse_dns_packet() - Converts DNS packet to a dict.

    Args:
        packet (Packet object) - The packet to parse.

    Returns:
        dict representing the DNS packet.
    """
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
        return output

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
        output["rr"] = _parse_dns_response(dns_packet.rr)
    if dns_packet.auth:
        output["auth"] = _parse_dns_response(dns_packet.auth)
    if dns_packet.ar:
        output["ar"] = _parse_dns_response(dns_packet.ar)

    return output


def _stdout_packet_json(packet_dict):
    """ _stdout_packet_json() - Prints DNS packet in JSON format to stdout.

    Args:
        packet_dict (dict) - dict derived from _parse_dns_packet()

    Returns:
        True
    """
    print(json.dumps(packet_dict))
    return True


def _timefilter_packet(packet_dict):
    # Replies are sorted rather than logged in the order in which
    # they were received because they aren't guaranteed to be in
    # the same order if queried more than once. Due to this
    # randomness, one query may end up occupying dozens of
    # elements.  Sorting will avoid duplicate elements in the
    # bloom filter when they are logically the same, thus,
    # reducing the required size of the filter.
    # Remove volatile fields before adding to bloom filter

    timefilter = Settings.get("timefilter")

    element_dict = copy.copy(packet_dict)
    element_dict.pop("timestamp")
    element_dict.pop("sport")
    element_dict.pop("dport")
    try:
        element_dict.pop("id")
    except KeyError:
        return False

    element = json.dumps(element_dict)

    if timefilter.lookup(element) is False:
        # TODO alert only if time baseline is complete
        # TODO greylist_miss_methods; for each method, do something with
        #      element_dict
        print("Not in filter:", json.dumps(element_dict, indent=4))
    timefilter.add(element)
    del element_dict

    return True


class Settings():
    """ Settings - Application settings object. """
    __config = {
        "timefilter": None,
        "interface": "eth0",
        "bpf": "port 53 or port 5353",
        "filter_size": 10000000,
        "filter_precision": 0.001,
        "filter_time": 60*60*24,
        "packet_methods": [
            _stdout_packet_json,
            _timefilter_packet,
        ],
    }

    @staticmethod
    def get(name):
        """ Settings.get() - Retrieve the value of a setting.

        Args:
            name (string) - Setting to retrieve.

        Returns:
            Contents of the setting on success, raises NameError if setting
            doesn't exist.
        """
        try:
            return Settings.__config[name]
        except KeyError:
            raise NameError("Not a valid setting for get():", name)


    @staticmethod
    def set(name, value):
        """ Settings.set() - Apply a setting.

        Args:
            name (string) - Name of setting.
            value         - Value to apply to setting.

        Returns:
            True on success. Raises NameError if setting doesnt exist.
        """
        if name in [x for x in Settings.__config]:
            Settings.__config[name] = value
            return True
        raise NameError("Not a valid setting for set():", name)


def main():
    """ main() - Entry point. """
    Settings.set("timefilter", TimeFilter(Settings.get("filter_size"),
                                          Settings.get("filter_precision"),
                                          Settings.get("filter_time")))

    capture = Sniffer(Settings.get("interface"), bpf=Settings.get("bpf"))
    capture.start()
    capture.setnonblock()

    while True:
        packet = capture.next()
        if not packet:
            # sleep() avoids 100% CPU use. Probably a better way to do this??
            sleep(0.05)
            continue

        output = _parse_dns_packet(packet)

        for method in Settings.get("packet_methods"):
            method(output)

    # Not Reached
    return True


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
