#!/usr/bin/env python3

""" greylost - DNS threat hunting. """

import os
import sys
import json
import copy
import argparse
import signal
import pickle
import atexit
import syslog
import statistics
from base64 import b64encode
from time import sleep, time
from datetime import datetime

import dnslib
from dmfrbloom.timefilter import TimeFilter

from pysniffer import Sniffer
from record_types import DNS_RECORD_TYPES


class RollingLog():
    def __init__(self, size):
        self.size = size
        self.log = [None for _ in range(size)]

    def add(self, data):
        self.log += [data]
        if len(self.log) > self.size:
            self.log = self.log[-1 * self.size:]

    def clear(self):
        self.log = []

def error_fatal(msg, exit_value=os.EX_USAGE):
    """ error_fatal() - Log an error and exit.

    Args:
        msg (str)  - Error message.
        exit_value - Value to pass to exit()

    Returns:
        Nothing.
    """
    error(msg)
    exit(exit_value)


def error(msg):
    """ error() - Log an error.

    Args:
        msg (str) - Error message.

    Returns:
        Nothing.
    """
    if not Settings.get("daemonize"):
        print("[-] %s" % msg, file=sys.stderr)
    syslog.syslog(msg)


def log(msg):
    """ log() - Log a message.

    Args:
        msg (str) - Message.

    Returns:
        Nothing
    """
    if not Settings.get("daemonize"):
        print("[+] %s" % msg)
    syslog.syslog(msg)


def parse_dns_response(response_list):
    """ parse_dns_response() - Parses DNS responses.

    Args:
        response_list (list) - Response list

    Returns:
        List of responses sorted by "rdata" key.
    """
    response_sorted_list = []
    for response in response_list:
        # <EDNS Option: Code=4 Data='0006629ac1efefda609ac1efefda'>
        if isinstance(response.rdata, dnslib.EDNSOption):
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


def parse_dns_packet(packet):
    """ parse_dns_packet() - Converts DNS packet to a dict.

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
        output["rr"] = parse_dns_response(dns_packet.rr)
    if dns_packet.auth:
        output["auth"] = parse_dns_response(dns_packet.auth)
    if dns_packet.ar:
        output["ar"] = parse_dns_response(dns_packet.ar)

    return output


def stdout_packet_json(packet_dict):
    """ stdout_packet_json() - Prints DNS packet in JSON format to stdout.

    Args:
        packet_dict (dict) - dict derived from parse_dns_packet()

    Returns:
        True
    """
    print(json.dumps(packet_dict))
    return True


def stdout_greylist_miss(packet_dict):
    """ stdout_greylist_miss() - Prints greylist misses to stdout.

    Args:
        packet_dict (dict) - dict containing information about the packet.

    Returns:
        True
    """
    print("Not in filter:", json.dumps(packet_dict, indent=4))
    return True


def check_greylist_ignore_list(packet_dict):
    """ check_greylist_ignore_list() - Check the greylist ignore list prior to
                                       adding to the greylist; this benign and
                                       trusted services such as Netflix that
                                       have a ton of IP addresses and subdomains
                                       from wasting space in the filter.

    Args:
        packet_dict (dict) - dict derived from parse_dns_packet()

    Returns:
        True if query should be ignored.
        False if query should be added to the greylist.
    """
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


def average_packet(packet):
    current = Settings.get("average_current")
    if packet:
        try:
            current[packet.saddr + " " + packet.daddr] += 1
        except KeyError:
            current[packet.saddr + " " + packet.daddr] = 1
        Settings.set("average_current", current)

    history = Settings.get("average_history")
    if (time() - Settings.get("average_last")) > 10:
        for key in current:
            if key in history.keys():
                history[key].add(current[key])
            else:
                history[key] = RollingLog(60 * 10) # 60 * 10
                history[key].add(current[key])

        # Reap expired host pairs
        current_keys = set(current.keys())
        new_history = history
        for key in history.copy():
            if key not in current_keys:
                new_history[key].add(0)
            if set(history[key].log) == {0}:
                new_history.pop(key)
        del history

        # Detect spikes in volume of traffic. This currently does not work
        # correctly. It detects spikes in traffic, but takes several minutes
        # or hours to correct itself.

        # TODO if current minute is N% higher than average?
        # TODO calculate median absolute deviation?
        for x in new_history:
            z = [i for i in new_history[x].log if i != None]
            if len(z[:-1]) > 1:
                print(x)
                mean = statistics.mean(z[:-1])
                stddev = statistics.stdev(z[:-1])
                print("    ",
                      "SPIKE" if stddev > mean else "",
                      max(z),
                      mean,
                      new_history[x].log[-1],
                      stddev)
                #if stddev > mean:
                #    print("SPIKE", x)

        Settings.set("average_history", new_history)
        Settings.set("average_current", {})
        Settings.set("average_last", time())


def timefilter_packet(packet_dict):
    """ timefilter_packet() - Add a packet to the greylist. This sorts and omits
                              volatile data such as port numbers, timestamps,
                              and the order of responses to prevent duplicate
                              elements from being added to the filter.

    Args:
        packet_dict (dict) - dict derived from parse_dns_packet()

    Returns:
        True if element was successfully added to the filter.
        False if element was not added to the filter.
    """

    # Check if domain is in ignore list.
    if check_greylist_ignore_list(packet_dict):
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

    # Are we still baselining DNS traffic?
    elapsed = time() - Settings.get("starttime")
    learning = not elapsed > Settings.get("filter_learning_time")

    if timefilter.lookup(element) is False and not learning:
        for method in Settings.get("greylist_miss_methods"):
            # Log everything rather than stripped down element_dict
            if method is _greylist_miss_log:
                _greylist_miss_log(packet_dict)
                continue
            method(element_dict)
    timefilter.add(element)
    del element_dict

    return True


def all_log(packet_dict):
    """all_log() - log a DNS packet

    Args:
        packet_dict (dict) - dict derived from parse_dns_packet()

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
        packet_dict (dict) - dict derived from parse_dns_packet()

    Returns:
        True if successful, False if unsuccessful
    """
    log_fd = Settings.get("greylist_miss_log_fd")
    if log_fd:
        log_fd.write(json.dumps(packet_dict) + "\n")
        log_fd.flush()
        return True
    return False


def not_dns_log(packet_dict):
    """not_dns_log() - log non-DNS protocol traffic

    Args:
        packet_dict (dict) - dict derived from parse_dns_packet()

    Returns:
        True if successful, False if unsuccessful
    """
    log_fd = Settings.get("not_dns_log_fd")
    if log_fd:
        log_fd.write(json.dumps(packet_dict) + "\n")
        log_fd.flush()
        return True
    return False


def parse_cli(): # pylint: disable=R0915,R0912
    """parse_cli() -- parse CLI arguments

    Args:
        None

    Returns:
        Nothing
    """
    description = "greylost by @dmfroberson"
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument(
        "--alllog",
        default=False,
        help="/path/to/all-log -- log of all DNS queries")

    parser.add_argument(
        "--notdnslog",
        default=False,
        help="/path/to/not-dns-log -- log of non-DNS protocol traffic")

    parser.add_argument(
        "--greylistmisslog",
        default=False,
        help="/path/to/greylist-miss-log -- log of greylist misses")

    parser.add_argument(
        "-b",
        "--bpf",
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
        "--filterfile",
        default=None,
        help="Path to timefilter's state file.")

    parser.add_argument(
        "-s",
        "--filtersize",
        default=10000000,
        type=int,
        help="Size of bloom filter")

    parser.add_argument(
        "--statistics",
        action="store_true",
        help="Toggle statistics collection")

    parser.add_argument(
        "--syslog",
        action="store_true",
        help="Toggle syslog logging")

    parser.add_argument(
        "-t",
        "--filtertime",
        default=60*60*24,
        type=int,
        help="Filter time")

    parser.add_argument(
        "--toggle-all-log",
        action="store_true",
        help="Toggle all log")

    parser.add_argument(
        "--toggle-not-dns-log",
        action="store_true",
        help="Toggle not DNS log")

    parser.add_argument(
        "--toggle-greylist-miss-log",
        action="store_true",
        help="Toggle greylist miss log")

    parser.add_argument(
        "-v",
        "--verbose",
        default=False,
        action="store_true",
        help="Increase verbosity")

    parser.add_argument(
        "-w",
        "--dumpfile",
        default=None,
        help="Write captured packets to a dumpfile")

    args = parser.parse_args()

    Settings.set("bpf", args.bpf)
    Settings.set("interface", args.interface)
    Settings.set("filter_size", args.filtersize)
    Settings.set("filter_precision", args.precision)
    Settings.set("filter_time", args.filtertime)
    Settings.set("filter_learning_time", args.learningtime)
    Settings.set("verbose", args.verbose)
    Settings.set("daemonize", args.daemonize)
    Settings.set("pcap_dumpfile", args.dumpfile)

    if args.syslog:
        Settings.toggle("syslog")
    if args.toggle_all_log:
        Settings.toggle("logging_all")
    if args.toggle_not_dns_log:
        Settings.toggle("logging_not_dns")
    if args.toggle_greylist_miss_log:
        Settings.toggle("logging_greylist_miss")
    if args.statistics:
        Settings.toggle("statistics")

    if args.filterfile:
        try:
            with open(args.filterfile, "ab"):
                pass
        except PermissionError as exc:
            error_fatal("Unable to open filter %s: %s" % (args.filterfile, exc),
                        exit_value=os.EX_OSFILE)
        Settings.set("filter_file", args.filterfile)

    if args.stdout:
        packet_methods = Settings.get("packet_methods")
        if stdout_packet_json not in packet_methods:
            packet_methods.append(stdout_packet_json)
            Settings.set("packet_methods", packet_methods)

        greylist_miss_methods = Settings.get("greylist_miss_methods")
        if stdout_greylist_miss not in greylist_miss_methods:
            greylist_miss_methods.append(stdout_greylist_miss)
            Settings.set("greylist_miss_methods", greylist_miss_methods)

    if args.logging:
        Settings.toggle("logging")
        if Settings.get("logging"):
            packet_methods = Settings.get("packet_methods")
            if all_log not in packet_methods:
                packet_methods.append(all_log)
                Settings.set("packet_methods", packet_methods)

            greylist_miss_methods = Settings.get("greylist_miss_methods")
            if _greylist_miss_log not in greylist_miss_methods:
                greylist_miss_methods.append(_greylist_miss_log)
                Settings.set("greylist_miss_methods", greylist_miss_methods)

    if args.pidfile:
        Settings.set("pid_file_path", args.pidfile)

    if args.ignore:
        Settings.set("greylist_ignore_domains_file", args.ignore)
        populate_greylist_ignore_list(args.ignore)

    if args.alllog:
        Settings.set("all_log", args.alllog)
    if args.notdnslog:
        Settings.set("not_dns_log", args.notdnslog)
    if args.greylistmisslog:
        Settings.set("greylist_miss_log", args.greylistmisslog)


def populate_greylist_ignore_list(ignore_file):
    """populate_greylist_ignore_list() - populate ignore list from file

    Args:
        ignore_file (str) - path to file

    Returns:
        Nothing on success. Exits with os.EX_OSFILE if the file doesn't exist
    """
    ignore_list = set()
    try:
        with open(ignore_file, "r") as ignore:
            for line in ignore:
                if line.rstrip() == "" or line.startswith("#"):
                    continue
                ignore_list.add(line.rstrip())
    except FileNotFoundError as exc:
        error_fatal("Unable to open ignore list %s: %s" % (ignore_file, exc),
                    exit_value=os.EX_OSFILE)
    Settings.set("greylist_ignore_domains", ignore_list)


def sig_hup_handler(signo, frame): # pylint: disable=W0613
    """sig_hup_handler() - Handle SIGHUP signals

    Args:
        signo (unused) - signal number
        frame (unused) - frame

    Returns:
        Nothing
    """
    log("Caught HUP signal.")
    log("Reloading log files.")
    if Settings.get("logging"):
        log_fds = ["all_log_fd", "greylist_miss_log_fd", "not_dns_log_fd"]
        for log_fd in log_fds:
            if not Settings.get(log_fd):
                continue
            Settings.get(log_fd).close()
            new_fd = open_log_file(Settings.get(log_fd[:-3])) # strip "_fd"
            Settings.set(log_fd, new_fd)

    if Settings.get("greylist_ignore_domains_file"):
        log("Reloading greylist ignore list")
        populate_greylist_ignore_list(Settings.get("greylist_ignore_domains_file"))
    # TODO rotate pcaps?


def startup_blurb():
    """startup_blurb() - show settings and other junk"""
    if not Settings.get("verbose"):
        return
    print("            interface: %s" % Settings.get("interface"))
    print("                  bpf: %s" % Settings.get("bpf"))
    print("          filter size: %s" % Settings.get("filter_size"))
    print("          filter time: %s" % Settings.get("filter_time"))
    print("     filter precision: %s" % Settings.get("filter_precision"))
    print("        learning time: %s" % Settings.get("filter_learning_time"))
    print("              logging: %s" % Settings.get("logging"))
    if Settings.get("logging"):
        print("             miss log: %s" % Settings.get("greylist_miss_log"))
        print("              all log: %s" % Settings.get("all_log"))
    if Settings.get("pcap_dumpfile"):
        print("        pcap dumpfile: %s" % Settings.get("pcap_dumpfile"))
    if Settings.get("greylist_ignore_domains_file"):
        print("          ignore list: %s" % Settings.get("greylist_ignore_domains_file"))

    method_types = ["packet_methods", "greylist_miss_methods", "not_dns_methods"]
    for method_type in method_types:
        if not Settings.get(method_type):
            continue
        count = 0
        sys.stdout.write(method_type.replace("_", " ").rjust(21) + ": ")
        for method in Settings.get(method_type):
            count += 1
            print(method)
            if count < len(Settings.get(method_type)):
                sys.stdout.write("".rjust(23))


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


def open_log_file(path):
    """open_log_file() - Open a log file for writing.

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


def open_log_files():
    """open_log_files() - Open up log files and store fds in Settings()"""
    # TODO what in the wild world of extreme sports is going on in here?
    if not Settings.get("logging"):
        return
    if Settings.get("all_log") and Settings.get("logging_all"):
        all_log_fd = open_log_file(Settings.get("all_log"))
        if all_log_fd:
            Settings.set("all_log_fd", all_log_fd)
        else:
            error("Something went wrong opening all_log")
    if Settings.get("greylist_miss_log") and Settings.get("logging_greylist_miss"):
        greylist_miss_fd = open_log_file(Settings.get("greylist_miss_log"))
        if greylist_miss_fd:
            Settings.set("greylist_miss_log_fd", greylist_miss_fd)
        else:
            error("Something went wrong opening greylist_miss_log")
    if Settings.get("not_dns_log") and Settings.get("logging_not_dns"):
        not_dns_fd = open_log_file(Settings.get("not_dns_log"))
        if not_dns_fd:
            Settings.set("not_dns_log_fd", not_dns_fd)
        else:
            error("Something went wrong with not_dns_log")


def save_timefilter_state():
    """" save_timefilter_state() - Save TimeFilter to disk

    Args:
        None.

    Returns:
        Nothing.
    """
    if Settings.get("filter_file"):
        log("Saving TimeFilter state to %s" % Settings.get("filter_file"))
        try:
            with open(Settings.get("filter_file"), "wb") as filterfile:
                try:
                    pickle.dump(Settings.get("timefilter"), filterfile)
                except KeyboardInterrupt: # Don't let user ^C and jack up filter
                    pass
        except PermissionError as exc:
            error_fatal("Unable to open filter %s: %s" % \
                        (Settings.get("filter_file"), exc),
                        os.EX_OSFILE)


def cleanup():
    """ cleanup() - Function to run at exit.

    Args:
        None.

    Returns:
        Nothing.
    """
    log("Exiting.")


def memory_free():
    """ memory_free() - Determine free memory on Linux hosts.

    Args:
        None.

    Returns:
        Free memory in bytes (int) on success.
        None on failure
    """
    # TODO: error check. not portable!!!
    with open("/proc/meminfo") as meminfo:
        for line in meminfo:
            if line.startswith("MemFree:"):
                return int(line.split()[1]) * 1024
    return None


class Settings():
    """ Settings - Application settings object. """
    __config = {
        "average_last": None,
        "average_current": {},
        "average_history": {},
        "statistics", False,
        "starttime": None,                          # Program start time
        "logging": False,                           # Toggle logging
        "logging_all": True,                        # Toggle all log
        "logging_greylist_miss": True,              # Toggle logging misses
        "logging_not_dns": True,                    # Toggle logging non-DNS
        "daemonize": False,                         # Toggle daemonization
        "timefilter": None,                         # TimeFilter object
        "interface": None,                          # Interface to sniff
        "bpf": None,                                # libpcap bpf filter
        "filter_file": None,                        # Path to filter state file
        "filter_size": None,                        # Size of filter
        "filter_precision": 0.001,                  # Filter accuracy
        "filter_time": 60*60*24,                    # Shelf life for elements
        "filter_learning_time": 0,                  # Baseline for N seconds
        "packet_methods": [timefilter_packet],      # Run these on all packets
        "not_dns_methods": [not_dns_log],           # Run these against non-DNS
        "greylist_miss_methods": [],                # Run these against misses
        "greylist_ignore_domains": set(),           # Set of domains to ignore
        "greylist_ignore_domains_file": None,       # Greylist ignore list
        "not_dns_log": "greylost-notdns.log",       # Path to not DNS logfile
        "not_dns_log_fd": None,                     # Not DNS file descriptor
        "greylist_miss_log": "greylost-misses.log", # Path to miss logfile
        "greylist_miss_log_fd": None,               # Miss log file descriptor
        "all_log": "greylost-all.log",              # Path to all logfile
        "all_log_fd": None,                         # All log file descriptor
        "verbose": False,                           # Verbose
        "pid_file_path": "greylost.pid",            # Path to PID file
        "pcap_dumpfile": None,                      # Path to pcap logfile
        "syslog": True,                             # Toggle syslog
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
            True on success. Raises NameError if setting doesn't exist.
        """
        if name in [x for x in Settings.__config]:
            Settings.__config[name] = value
            return True
        raise NameError("Not a valid setting for set():", name)


    @staticmethod
    def toggle(name):
        """ Settings.toggle() - Toggle a setting: True->False, False->True.

        Args:
            name (string) - Name of setting to toggle.

        Returns:
            Value of setting after it has been toggled on success.
            Raises NameError if setting doesn't exist.
            Raises TypeError if setting isn't a bool.
        """
        try:
            if isinstance(Settings.__config[name], bool):
                Settings.__config[name] = not Settings.__config[name]
                return Settings.__config[name]
            raise TypeError("Setting %s is not a boolean." % name)
        except KeyError:
            raise NameError("Not a valid setting for toggle():", name)


def main(): # pylint: disable=R0912,R0915
    """ main() - Entry point. """
    parse_cli()

    # Set up logging
    syslog.openlog(ident="greylost", logoption=syslog.LOG_PID)
    open_log_files()
    syslog.syslog("Started")

    # Fork into the background, if desired.
    if Settings.get("daemonize"):
        try:
            pid = os.fork()
            if pid > 0:
                exit(os.EX_OK)
        except OSError as exc:
            error_fatal("fork(): %s" % exc, exit_value=os.EX_OSERR)

    # Write PID file
    write_pid_file(Settings.get("pid_file_path"))

    # Signal and atexit handlers
    signal.signal(signal.SIGHUP, sig_hup_handler)
    atexit.register(save_timefilter_state)
    atexit.register(cleanup)

    # Used for scheduling...
    Settings.set("starttime", time())
    Settings.set("average_last", time())

    # Create timefilter
    # TODO save other metadata to disk; start time, filter attributes, etc.
    #      i think this will cause problems if invoked again with different
    #      values while using a filter file, but have not tested yet.
    try:
        Settings.set("timefilter", TimeFilter(Settings.get("filter_size"),
                                              Settings.get("filter_precision"),
                                              Settings.get("filter_time")))
    except MemoryError:
        timefilter = TimeFilter(1, 0.1, 1) # Dummy filter for ideal_size()
        error_fatal("Out of memory. Filter requires %d bytes. %d available." % \
                    (timefilter.ideal_size(Settings.get("filter_size"),
                                           Settings.get("filter_precision")),
                     memory_free()),
                    exit_value=os.EX_SOFTWARE)

    # Restore TimeFilter's saved state from disk
    if Settings.get("filter_file"):
        try:
            with open(Settings.get("filter_file"), "rb") as filterfile:
                timefilter = filterfile.read()
        except FileNotFoundError:
            pass
        if bool(timefilter):
            # TODO other filter settings? currently not saving these and
            #      relying on CLI/config to be correct.
            try:
                Settings.set("timefilter", pickle.loads(timefilter))
            except Exception as exc: # pylint: disable=W0703
                error_fatal("Failed to unpickle time filter %s: %s" % \
                            (Settings.get("filter_file"), exc),
                            exit_value=os.EX_SOFTWARE)
            del timefilter

    # Display startup settings (debugging)
    startup_blurb()

    # Start sniffer
    capture = Sniffer(Settings.get("interface"), bpf=Settings.get("bpf"))
    result = capture.start()
    if not result[0]:
        error_fatal("Unable to open interface %s for sniffing: %s" % \
                    (Settings.get("interface"), result[1]),
                    exit_value=os.EX_NOINPUT)
    capture.setnonblock()

    # Open pcap logfile if desired
    if Settings.get("pcap_dumpfile"):
        result = capture.dump_open(Settings.get("pcap_dumpfile"))
        if not result[0]:
            error_fatal("Unable to open %s for writing: %s" % \
                       (Settings.get("pcap_dumpfile"), result[1]),
                        exit_value=os.EX_OSFILE)

    while True:
        packet = capture.next()
        if packet is False:
            error_fatal("Interface %s went down. Exiting." % \
                        Settings.get("interface"),
                        exit_value=os.EX_UNAVAILABLE)

        # Detect spikes in DNS traffic
        if Settings.get("statistics"):
            average_packet(packet)

        if packet is None:
            sleep(0.05) # Avoid 100% CPU
            continue

        output = parse_dns_packet(packet)

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
