""" pysniffer - libpcap-based sniffer. """

# pylint: disable=I1101
import pcapy

from pypacket import Packet


class Sniffer():
    """ Sniffer() - Sniffer object.

    Attributes:
        interface (string) - Interface to sniff on.
        promisc (int)      - Promiscuous mode; 1 = yes, 0 = no
        bpf (str)          - BPF filter for sniffer.
        snaplen (int)      - snaplen
        timeout (int)      - timeout.
        sniffer            - fd used by libpcap.
    """
    # pylint: disable=R0913
    def __init__(self, interface, promisc=1, bpf="", snaplen=65535, timeout=100):
        self.interface = interface
        self.promisc = promisc
        self.bpf = bpf
        self.snaplen = snaplen
        self.timeout = timeout
        self.sniffer = None
        self.dumper = None
        self.dumpfile = None

    def start(self):
        """ Sniffer.start() - Start the sniffer.

        Args:
            None.

        Returns:
            Nothing.
        """
        self.sniffer = pcapy.open_live(self.interface,
                                       self.snaplen,
                                       self.promisc,
                                       self.timeout)
        self.sniffer.setfilter(self.bpf)

    def next(self):
        # TODO catch exception if interface goes down and exit gracefully
        """ Sniffer.next() - Get next packet from sniffer.

        Args:
            None.

        Returns:
            Packet object of the next packet on success, None on failure.
        """
        header, packet = self.sniffer.next()

        if packet:
            if self.dumper:
                self.dumper.dump(header, packet)
            return Packet(packet)
        return None
        #return Packet(packet) if packet else None

    def setnonblock(self):
        """ Sniffer.setnonblock() - set sniffer to non-blocking mode.

        Args:
            None.

        Returns:
            Nothing.
        """
        # TODO error check
        self.sniffer.setnonblock(1)

    def dump_open(self, path):
        """ Sniffer.dump_open() - open dumpfile to write pcaps to.

        Args:
            path (str) - path to dumpfile.

        Returns:
            tuple: (True/False, None/descriptive failure message)
        """
        self.dumpfile = path
        try:
            self.dumper = self.sniffer.dump_open(path)
        except pcapy.PcapError as exc:
            return (False, exc)
        return (True, None)

    def dump_close(self):
        """ Sniffer.dump_close() - close pcap dumpfile.

        Args:
            None.

        Returns:
            Nothing.
        """
        # TODO error check
        self.dumper.close()
