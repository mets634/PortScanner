#!/usr/bin/env python

from scanner import Parser, PortScanner
import sys


def main():
    print '[WARNING] Use scanner responsibly...'

    network, ports, scan = Parser().parse()
    for ip in network:
        print

        scanner = PortScanner(str(ip))  # create port scanner for ip

        # check if host is up
        if not scanner.check_host():  # host is down
            choice = raw_input('Should I attempt to scan anyway? (yes/no) ')
            if choice != 'yes':
                continue

        if scan == 0:
            oports = scanner.full_scan(ports)
        else:
            oports = scanner.null_scan(ports)
        os = scanner.determine_os()
        if len(oports) > 0:
            print '[*] Open ports -> ' + ', '.join([str(port) for port in oports])
        else:
            print '[*] No open ports'
        print '[*] OS -> ' + os

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
