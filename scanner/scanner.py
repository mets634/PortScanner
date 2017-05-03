"""A file exposing port scanner class."""

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from numpy import mean

conf.verb = 0


class PortScanner(object):
    """A class that performs port scanning."""

    def __init__(self, ip):
        """Class ctor."""

        self.__ip = ip
        self.__received_pkts = []

    def determine_os(self):
        """A method to determine the OS of
        scanned computer using received pkts
        :param pkt: A list of received pkts.
        """

        MAX_ERROR_MARGIN = 0.3

        if len(self.__received_pkts) == 0:
            return 'OS not found'

        ttl = mean(map(lambda p: p[IP].ttl, self.__received_pkts))

        print 'ttl -> %s' % str(ttl)

        if ttl > 128:
            return 'iOS 12.4 (Cisco Routers)'
        if ttl > 64:
            return 'Windows'

        # ttl < 64
        return 'Linux'

    def full_scan(self, ports):
        """
        A method to do a FULL scan.
        :param ports: A list of ports to scan.
        :return: A list of open ports.
        """

        open_ports = []

        print '\n[DEBUG] Starting FULL scan on IP %s...' % self.__ip

        ip = IP(dst=self.__ip)

        for port in ports:
            print '\n[DEBUG] Scanning port %s...' % port

            syn = ip / TCP(dport=port, flags='S')  # create SYN pkt

            print '[DEBUG] Sending SYN...'
            synack = sr1(syn, timeout=7, retry=1)  # await SYN-ACK

            if str(type(synack)) == "<type 'NoneType'>":
                print '[DEBUG] Timeout occured'
                continue

            self.__received_pkts.append(synack)  # record received pkt

            if synack[TCP].flags == 0x12:  # is an open port
                print '[DEBUG] Got Syn-Ack (port open). Sending Rst-Ack...'

                ackrst = ip / TCP(dport=port, flags='RA',
                             seq=synack[TCP].ack + 1, ack=syn[TCP].seq + 1)  # create ACK-RST pkt
                send(ackrst)  # end the connection
                open_ports.append(port)  # record as open port
            else:
                print '[DEBUG] Port closed\n'

        return open_ports

    def null_scan(self, ports):
        """
        A method to do a NULL scan.
        :param ports: A list of ports to scan.
        :return: A list of open ports.
        """

        print '\n[DEBUG] Starting NULL scan on IP %s...' % self.__ip

        open_ports = []

        ip = IP(dst=self.__ip)

        for port in ports:
            print '\n[DEBUG] Scanning port %s...' % port

            pkt = ip / TCP(dport=port, flags='')  # create pkt with no flags
            print '[DEBUG] Sending empty TCP pkt...'

            ans, unans = sr(pkt, timeout=7, retry=1)

            self.__received_pkts.extend(ans)  # record received pkt

            if len(ans) == 0:  # no reply, port is open
                print '[DEBUG] No reply (open port)'
                open_ports.append(port)
            else:
                print '[DEBUG] Got reply (port closed)'

        return open_ports
