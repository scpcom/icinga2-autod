#!/bin/sh
# On Windows Server run:
# netsh dhcp server dump > dhcp.txt
grep ' Add reservedip ' dhcp.txt | cut -d ' ' -f 8-10 | tr -d '"' | tr ' ' ';' > discovered_hosts_dhcp.csv
