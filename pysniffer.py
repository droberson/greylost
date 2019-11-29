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
        _, packet = self.sniffer.next()
        return Packet(packet) if packet else None

    def setnonblock(self):
        """ Sniffer.setnonblock() - set sniffer to non-blocking mode. """
        # TODO error check
        self.sniffer.setnonblock(1)
