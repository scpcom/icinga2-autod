#!/usr/bin/env python
import csv
import os
import re
macp_filename = 'discovered_hosts_mac_ports.csv'
macf_filename = macp_filename[:-14] + '_mac_found.csv'
lldt_filenames = [f for f in os.listdir('.') if re.match(r'.*_mac_lldp\.csv', f)]
mact_filenames = [f for f in os.listdir('.') if re.match(r'.*_mac_table\.csv', f)]
macp_filenames = [f for f in os.listdir('.') if re.match(r'.*_mac_ports\.csv', f)]

lldt_reader = list()
for lldt_filename in lldt_filenames:
    with open(lldt_filename) as lldt_file:
        lldt_reader += list( csv.reader(lldt_file, delimiter=';') )

mact_reader = list()
for mact_filename in mact_filenames:
    with open(mact_filename) as mact_file:
        mact_reader += list( csv.reader(mact_file, delimiter=';') )

macp_reader = list()
for macp_filename in macp_filenames:
    with open(macp_filename) as macp_file:
        macp_reader += list( csv.reader(macp_file, delimiter=';') )

macf_f = open(macf_filename, 'w')
prev_maca = ''
arpa = ''
for macp in macp_reader:
    macp_hostname = macp[3].split('.')[0]
    macp_ip = macp[2]
    port_share = 999999
    port_data = {}
    if macp[1] == 'arp':
        arpa = macp[0]

    for lldt in lldt_reader:
        if macp[0] == lldt[0]:
            pcnt = 0
            port_share = pcnt
            port_data = lldt
            pidx=1
            port_hostname = port_data[pidx+3].split('.')[0]
            port_ip = port_data[pidx+2]
            local_port = ''
            for pldt in lldt_reader:
                if pldt[3] == macp_ip:
                    for pacp in macp_reader:
                        if pacp[0] == pldt[0] and pacp[2] == port_ip:
                            local_port = pldt[1]
            if local_port == '' and macp[0] == arpa:
                local_port = 'arp'

            print macp[0] + ' ' + macp_ip + ' ' + macp_hostname + ' port ' + macp[1] + ' ('+local_port+')' + ' found on ' + port_ip + ' ' + port_hostname + ' port ' + port_data[1] + ' (' + str(port_share) + ')'
            macf_f.write(macp[0] + ';' + macp_ip + ';' + macp_hostname + ';' + local_port + ';' + port_ip + ';' + port_hostname + ';' + port_data[1] + ';' + str(port_share) +'\n')
            prev_maca = macp[0]

    for mact in mact_reader:
        if macp[0] == mact[0]:
            pcnt = 0
            for pacp in mact_reader:
                if mact[2] == pacp[2] and mact[1] == pacp[1]:
                    pcnt += 1
            if pcnt < port_share:
                port_share = pcnt
                port_data = mact

    if port_share < 999999 and port_share > 0:
        pidx=0
        port_hostname = port_data[pidx+3].split('.')[0]
        port_ip = port_data[pidx+2]
        if  macp[0] != prev_maca:
            local_port = ''
            if macp[0] == arpa:
                local_port = 'arp'
            print macp[0] + ' ' + macp_ip + ' ' + macp_hostname + ' port ' + macp[1] + ' ('+local_port+')' + ' found on ' + port_ip + ' ' + port_hostname + ' port ' + port_data[1] + ' (' + str(port_share) + ')'
            macf_f.write(macp[0] + ';' + macp_ip + ';' + macp_hostname + ';' + local_port + ';' + port_ip + ';' + port_hostname + ';' + port_data[1] + ';' + str(port_share) +'\n')
            prev_maca = macp[0]
    elif macp[1] == 'arp' and port_share > 0:
        print macp[0] + ' ' + macp_ip + ' port ' + macp[1] + ' not found'
macf_f.close()
