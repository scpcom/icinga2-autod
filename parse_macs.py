#!/usr/bin/env python
import csv
macp_filename = 'discovered_hosts_mac_ports.csv'
mact_filename = 'hosts_mac_table.csv'
macf_filename = macp_filename[:-14] + '_mac_found.csv'
macf_f = open(macf_filename, 'w')
with open(macp_filename) as macp_file:
    with open(mact_filename) as mact_file:
        macp_reader = list( csv.reader(macp_file, delimiter=';') )
        mact_reader = list( csv.reader(mact_file, delimiter=';') )
        prev_maca = ''
        for macp in macp_reader:
            macp_hostname = macp[3].split('.')[0]
            port_share = 999999
            port_data = {}
            for mact in mact_reader:
                if macp[0] == mact[0]:
                    pcnt = 0
                    for pacp in mact_reader:
                        if mact[2] == pacp[2] and mact[1] == pacp[1]:
                            pcnt += 1 
                    if pcnt < port_share:
                        port_share = pcnt
                        port_data = mact
            if port_share < 999999:
                port_hostname = port_data[3].split('.')[0]
                if  macp[0] != prev_maca:
                    print macp[0] + ' ' + macp[2] + ' ' + macp_hostname + ' found on ' + port_data[2] + ' ' + port_hostname + ' port ' + port_data[1] + ' (' + str(port_share) + ')'
                    macf_f.write( macp[0] + ';' + macp[2] + ';' + macp_hostname + ';' + port_data[2] + ';' + port_hostname + ';' + port_data[1] + ';' + str(port_share) +'\n')
                    prev_maca = macp[0]
            elif macp[1] == 'arp':
                print macp[0] + ' ' + macp[2] + ' port ' + macp[1] + ' not found'
macf_f.close()
