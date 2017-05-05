"""This file exposes argument handling class"""

# USAGE: IP/IPRange/SubNet -p Number/NumberRange -t 0/1
#
# p -> ports to scan.
# t -> 0 = NULL scan, 1 = FULL scan.

from optparse import OptionParser
from netaddr import IPNetwork, IPRange
import sys


class Parser(object):
    """A class representing a CMD-line parser"""

    def __init__(self):
        """Class ctor. Initiate parser."""

        # parser constants
        self.usage = 'USAGE: ./main.py IP/IPRange/SubNet -p PORT/PORTRange -t 0/1'
        # ip_help = 'IP/IPRange/SubNet'
        self.ports_help = 'Number/NumberRange'
        self.type_help = '0 = NULL scan, 1 = FULL scan'

        # create arg parser
        self.parser = OptionParser(usage=self.usage)

        self.parser.add_option('-p', '--port', action='store', dest='ports', help=self.ports_help)
        self.parser.add_option('-t', '--type', action='store', dest='scan_type', help=self.type_help)

    def parse(self):
        """Parse the arguments into usable data-types."""

        (options, args) = self.parser.parse_args()

        cond = len(args) < 1 \
               or not options.scan_type \
               or not options.ports \
               or int(options.scan_type) not in [0, 1]

        if cond:  # missing IPRange or illegal scan type
            print self.usage
            sys.exit(0)

        return self.ip_str_to_network(args[0]), \
               self.port_str_to_numrange(options.ports), \
               int(options.scan_type)

    @staticmethod
    def port_str_to_numrange(str_range):
        return sum(((list(range(*[int(j) + k for k, j in enumerate(i.split('-'))]))
                    if '-' in i else [int(i)]) for i in str_range.split(',')), [])

    @staticmethod
    def ip_str_to_network(str_range):
        if '-' in str_range:
            index = str_range.index('-')
            return IPRange(str_range[:index], str_range[index+1:])
        return IPNetwork(str_range)
