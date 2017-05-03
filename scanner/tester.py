from scanner import PortScanner
import sys

try:
    scanner = PortScanner("62.219.14.116")
    print scanner.full_scan([443, 80, 20, 23, 22])
except KeyboardInterrupt:
    sys.exit(0)
