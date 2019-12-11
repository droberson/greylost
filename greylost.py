#!/usr/bin/env python3

""" greylost - DNS threat hunting
"""

import os
import sys
import json
import copy
import argparse
import signal
from base64 import b64encode
from time import sleep, time
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
        # <EDNS Option: Code=4 Data='0006629ac1efefda609ac1efefda'>
        if type(response.rdata) == dnslib.EDNSOption:
            rdata = {"code": response.rdata.code, "data": response.rdata.data}
        else:
            rdata = str(response.rdata)

        response_sorted_list.append({"rname": str(response.rname),
                                     "rtype": DNS_RECORD_TYPES[response.rtype],
                                     "rtype_id": response.rtype,
                                     "rclass": response.rclass,
                                     "rdata": rdata,
                                     "ttl": response.ttl})
    # Sort results to avoid logical duplicates in the bloom filter
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
        if packet.data:
            # TODO don't encode if everything is printable
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


def _stdout_greylist_miss(packet_dict):
    """ _stdout_greylist_miss() - Prints greylist misses to stdout.

    Args:
        packet_dict (dict) - dict containing information about the packet.

    Returns:
        True
    """
    print("Not in filter:", json.dumps(packet_dict, indent=4))
    return True


def _check_greylist_ignore_list(packet_dict):
    try:
        for question in packet_dict["questions"]:
            for ignore in Settings.get("greylist_ignore_domains"):
                if question["qname"].endswith(ignore):
                    return True
                # .example.com. matches foo.example.com. and example.com.
                if ignore.startswith(".") and question["qname"].endswith(ignore[1:]):
                    return True
    except KeyError:
        pass
    return False
    # TODO should I check responses too? need to collect more data...
    # for response in ["rr", "ar", "auth"]:
    #     try:
    #         for chk in packet_dict[response]:
    #             for ign in Settings.get("greylist_ignore_domains"):
    #                 if chk["rdata"].endswith(ign) or chk["rname"].endswith(ign):
    #                     return True
    #                 # .example.com. matches foo.example.com. and example.com.
    #                 if ign[0] == "." and chk["rname"].endswith(ign[1:]):
    #                     return True
    #                 if ign[0] == "." and chk["rdata"].endswith(ign[1:]):
    #                     return True
    #     except KeyError:
    #         pass
    # return False


def _timefilter_packet(packet_dict):
    # Replies are sorted rather than logged in the order in which
    # they were received because they aren't guaranteed to be in
    # the same order if queried more than once. Due to this
    # randomness, one query may end up occupying dozens of
    # elements.  Sorting will avoid duplicate elements in the
    # bloom filter when they are logically the same, thus,
    # reducing the required size of the filter.

    # Check if domain is in ignore list.
    if _check_greylist_ignore_list(packet_dict):
        return False

    timefilter = Settings.get("timefilter")

    # Remove volatile fields before adding to bloom filter
    element_dict = copy.copy(packet_dict)
    element_dict.pop("timestamp")
    element_dict.pop("sport")
    element_dict.pop("dport")
    try:
        element_dict.pop("id")
    except KeyError:
        return False

    element = json.dumps(element_dict)
    elapsed = time() - Settings.get("starttime")
    learning = not elapsed > Settings.get("filter_learning_time")

    if timefilter.lookup(element) is False and not learning:
        for method in Settings.get("greylist_miss_methods"):
            # log everything rather than stripped down element_dict
            if method is _greylist_miss_log:
                _greylist_miss_log(packet_dict)
                continue
            method(element_dict)
    timefilter.add(element)
    del element_dict

    return True


def _all_log(packet_dict):
    """_all_log() - log a DNS packet

    Args:
        packet_dict (dict) - dict derived from _parse_dns_packet()

    Returns:
        True if successful, False if unsuccessful
    """

    log_fd = Settings.get("all_log_fd")
    if log_fd:
        log_fd.write(json.dumps(packet_dict) + "\n")
        log_fd.flush()
        return True
    return False


def _greylist_miss_log(packet_dict):
    """_greylist_miss_log() - log a greylist miss

    Args:
        packet_dict (dict) - dict derived from _parse_dns_packet()

    Returns:
        True if successful, False if unsuccessful
    """
    log_fd = Settings.get("greylist_miss_log_fd")
    if log_fd:
        log_fd.write(json.dumps(packet_dict) + "\n")
        log_fd.flush()
        return True
    return False


def _not_dns_log(packet_dict):
    """_not_dns_log() - log non-DNS protocol traffic

    Args:
        packet_dict (dict) - dict derived from _parse_dns_packet()

    Returns:
        True if successful, False if unsuccessful
    """
    log_fd = Settings.get("not_dns_log_fd")
    if log_fd:
        log_fd.write(json.dumps(packet_dict) + "\n")
        log_fd.flush()
        return True
    return False


def parse_cli():
    """parse_cli() -- parse CLI arguments

    Args:
        None

    Returns:
        Nothing
    """
    description = "greylost by @dmfroberson"
    parser = argparse.ArgumentParser(description=description)

    # TODO set log file paths
    parser.add_argument(
        "-b",
        "--bpf",
        type=str,
        default="port 53 or port 5353",
        help="BPF filter to apply to the sniffer")

    parser.add_argument(
        "-d",
        "--daemonize",
        default=False,
        action="store_true",
        help="Daemonize")

    parser.add_argument(
        "--learningtime",
        default=0,
        type=int,
        help="Time to baseline queries before alerting on greylist misses")

    parser.add_argument(
        "--logging",
        default=False,
        action="store_true",
        help="Toggle logging")

    parser.add_argument(
        "--ignore",
        default=None,
        help="File containing list of domains to ignore when greylisting")

    parser.add_argument(
        "-i",
        "--interface",
        default="eth0",
        help="Interface to sniff")

    parser.add_argument(
        "-o",
        "--stdout",
        action="store_true",
        default=False,
        help="Toggle stdout output")

    parser.add_argument(
        "-p",
        "--precision",
        default=0.001,
        type=int,
        help="Precision of bloom filter. Ex: 0.001")

    parser.add_argument(
        "-r",
        "--pidfile",
        default=None,
        help="Path to PID file")

    parser.add_argument(
        "-s",
        "--filtersize",
        default=10000000,
        type=int,
        help="Size of bloom filter")

    parser.add_argument(
        "-t",
        "--filtertime",
        default=60*60*24,
        type=int,
        help="Filter time")

    parser.add_argument(
        "-v",
        "--verbose",
        default=False,
        action="store_true")

    args = parser.parse_args()

    Settings.set("bpf", args.bpf)
    Settings.set("interface", args.interface)
    Settings.set("filter_size", args.filtersize)
    Settings.set("filter_precision", args.precision)
    Settings.set("filter_time", args.filtertime)
    Settings.set("filter_learning_time", args.learningtime)
    Settings.set("verbose", args.verbose)
    Settings.set("daemonize", args.daemonize)

    if args.stdout:
        packet_methods = Settings.get("packet_methods")
        if _stdout_packet_json not in packet_methods:
            packet_methods.append(_stdout_packet_json)
            Settings.set("packet_methods", packet_methods)

        greylist_miss_methods = Settings.get("greylist_miss_methods")
        if _stdout_greylist_miss not in greylist_miss_methods:
            greylist_miss_methods.append(_stdout_greylist_miss)
            Settings.set("greylist_miss_methods", greylist_miss_methods)

    if args.logging:
        Settings.set("logging", not Settings.get("logging"))

        packet_methods = Settings.get("packet_methods")
        if _all_log not in packet_methods:
            packet_methods.append(_all_log)
            Settings.set("packet_methods", packet_methods)

        greylist_miss_methods = Settings.get("greylist_miss_methods")
        if _greylist_miss_log not in greylist_miss_methods:
            greylist_miss_methods.append(_greylist_miss_log)
            Settings.set("greylist_miss_methods", greylist_miss_methods)

    if args.pidfile:
        Settings.set("pid_file_path", args.pidfile)

    if args.ignore:
        Settings.set("greylist_ignore_domains_file", args.ignore)
        populate_greylist_ignore_list()


def populate_greylist_ignore_list():
    ignore_list = set()
    ignore_file = Settings.get("greylist_ignore_domains_file")
    try:
        with open(ignore_file, "r") as ignore:
            for line in ignore:
                if line.rstrip() == "" or line.startswith("#"):
                    continue
                ignore_list.add(line.rstrip())
    except FileNotFoundError as exc:
        print("[-] Unable to open ignore list %s: %s" % (ignore_file, exc))
        exit(os.EX_USAGE)
    Settings.set("greylist_ignore_domains", ignore_list)


def sig_hup_handler(signo, frame): # pylint: disable=W0613
    """sig_hup_handler() - Handle SIGHUP signals

    Args:
        signo (unused) - signal number
        frame (unused) - frame

    Returns:
        Nothing
    """
    if Settings.get("logging"):
        if Settings.get("all_log_fd"):
            Settings.get("all_log_fd").close()
            all_log_fd = open_log_file(Settings.get("all_log"))
            Settings.set("all_log_fd", all_log_fd)
        if Settings.get("greylist_miss_log_fd"):
            Settings.get("greylist_miss_log_fd").close()
            greylist_miss_fd = open_log_file(Settings.get("greylist_miss_log"))
            Settings.set("greylist_miss_log_fd", greylist_miss_fd)
        if Settings.get("not_dns_log_fd"):
            Settings.get("not_dns_log_fd").close()
            not_dns_fd = open_log_file(Settings.get("not_dns_log"))
            Settings.set("not_dns_log_fd", not_dns_fd)


def open_log_file(path):
    """open_log_file() - open a log file and store its fd in Settings()

    Args:
        path (str) - Path to log file

    Returns:
        fd on success, None on failure
    """
    try:
        log_fd = open(path, "a")
    except PermissionError:
        return None
    log_fd.flush()
    return log_fd


def startup_blurb():
    """startup_blurb() - show settings and other junk"""
    if not Settings.get("verbose"):
        return
    print("       interface: %s" % Settings.get("interface"))
    print("             bpf: %s" % Settings.get("bpf"))
    print("     filter size: %s" % Settings.get("filter_size"))
    print("     filter time: %s" % Settings.get("filter_time"))
    print("filter precision: %s" % Settings.get("filter_precision"))
    print("   learning time: %s" % Settings.get("filter_learning_time"))
    print("         logging: %s" % Settings.get("logging"))
    if Settings.get("logging"):
        print("        miss log: %s" % Settings.get("greylist_miss_log"))
        print("         all log: %s" % Settings.get("all_log"))

    count = 0
    methods = len(Settings.get("packet_methods"))
    if Settings.get("packet_methods"):
        sys.stdout.write("  packet methods: ")
        for method in Settings.get("packet_methods"):
            count += 1
            print(method)
            if count < methods:
                sys.stdout.write("                  ")

    count = 0
    methods = len(Settings.get("greylist_miss_methods"))
    if Settings.get("greylist_miss_methods"):
        sys.stdout.write("    miss methods: ")
        for method in Settings.get("greylist_miss_methods"):
            count += 1
            print(method)
            if count < methods:
                sys.stdout.write("                  ")

    count = 0
    methods = len(Settings.get("not_dns_methods"))
    if Settings.get("not_dns_methods"):
        sys.stdout.write(" not dns methods: ")
        for method in Settings.get("not_dns_methods"):
            count += 1
            print(method)
            if count < methods:
                sys.stdout.write("                  ")


def write_pid_file(path):
    """write_pid_file() - Write current PID to specified path

    Args:
        path (str) - path to PID file

    Returns:
        True if successful, False if unsuccessful
    """
    try:
        with open(path, "w") as pidfile:
            pidfile.write(str(os.getpid()))
    except PermissionError:
        return False
    return True


def open_log_files():
    """open_log_files() - Open up log files and store fds in Settings()"""
    if not Settings.get("logging"):
        return
    if Settings.get("all_log"):
        all_log_fd = open_log_file(Settings.get("all_log"))
        if all_log_fd:
            Settings.set("all_log_fd", all_log_fd)
        else:
            print("something went wrong opening all_log")
    if Settings.get("greylist_miss_log"):
        greylist_miss_fd = open_log_file(Settings.get("greylist_miss_log"))
        if greylist_miss_fd:
            Settings.set("greylist_miss_log_fd", greylist_miss_fd)
        else:
            print("something went wrong opening greylist_miss_log")
    if Settings.get("not_dns_log"):
        not_dns_fd = open_log_file(Settings.get("not_dns_log"))
        if not_dns_fd:
            Settings.set("not_dns_log_fd", not_dns_fd)
        else:
            print("something went wrong with not_dns_log")


class Settings():
    """ Settings - Application settings object. """
    __config = {
        "starttime": None,
        "logging": False,
        "daemonize": False,
        "timefilter": None,
        "interface": None,
        "bpf": None,
        "filter_size": None,
        "filter_precision": 0.001,
        "filter_time": 60*60*24, # 1 day
        "filter_learning_time": 0, # set to zero if you dont want to learn
        "packet_methods": [_timefilter_packet],
        "not_dns_methods": [_not_dns_log],
        "greylist_miss_methods": [],
        "greylist_ignore_domains": set(),
        "greylist_ignore_domains_file": None,
        "not_dns_log": "greylost-notdns.log",
        "not_dns_log_fd": None,
        "greylist_miss_log": "greylost-misses.log",
        "greylist_miss_log_fd": None,
        "all_log": "greylost-all.log",
        "all_log_fd": None,
        "verbose": False,
        "pid_file_path": "greylost.pid",
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
    parse_cli()

    if Settings.get("daemonize"):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as exc:
            print("fork(): %s" % exc, file=sys.stderr)
            sys.exit(1)
        write_pid_file(Settings.get("pid_file_path"))

    # Signal handlers
    signal.signal(signal.SIGHUP, sig_hup_handler)

    # Random start of program stuff
    Settings.set("starttime", time())
    Settings.set("timefilter", TimeFilter(Settings.get("filter_size"),
                                          Settings.get("filter_precision"),
                                          Settings.get("filter_time")))
    startup_blurb()
    open_log_files()

    # Start sniffer
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

        # Do stuff to non-DNS packets
        try:
            if output["payload"]:
                for method in Settings.get("not_dns_methods"):
                    method(output)
        except KeyError:
            pass

        # Do stuff to packets
        for method in Settings.get("packet_methods"):
            method(output)

    # Not Reached
    return True


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
