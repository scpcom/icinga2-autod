#!/usr/bin/env python3
import csv
import os
import re
macp_filename = 'discovered_hosts_mac_ports.csv'
macf_filename = macp_filename[:-14] + '_mac_found.csv'
deps_filename = macp_filename[:-14] + '_deps.conf'
dups_filename = macp_filename[:-14] + '_deps_dups.conf'
revs_filename = macp_filename[:-14] + '_deps_revs.conf'
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
macf_f.write('port-mac;port-host-ip;port-host-name;port-id;remote-host-ip;remote-host-name;remote-id;shared-count' +'\n');
deps_f = open(deps_filename, 'w')
dups_f = open(dups_filename, 'w')
revs_f = open(revs_filename, 'w')
deps_list = ''
foun_list = ''
prev_maca = ''
arpa = ''
for macp in macp_reader:
    macp_hostname = macp[3].split('.')[0]
    macp_ip = macp[2]
    if macp_hostname == '':
        macp_hostname = macp_ip
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
            if port_hostname == '':
                port_hostname = port_ip

            local_port = ''
            for pldt in lldt_reader:
                if pldt[3] == macp_ip:
                    for pacp in macp_reader:
                        if pacp[0] == pldt[0] and pacp[2] == port_ip:
                            local_port = pldt[1]
            if local_port == '' and macp[0] == arpa:
                local_port = 'arp'
            local_service = 'snmp-int-port'+local_port
            if local_port == 'arp':
                local_service = 'ping4'
            elif local_port != '':
                local_service = 'snmp-int-port'+str(int(local_port))
            parent_service = 'snmp-int-port'+str(int(port_data[1]))

            deps_skip = 0
            deps_reve = 0
            deps_dupl = 0
            port_dupl = 0
            for deps in deps_list.split('\n'):
                deps = deps.split(';')
                if len(deps) > 3 and deps[0] == macp_hostname and deps[2] == port_hostname and deps[3] == port_data[1]:
                    deps_skip = 1
                    break
                elif len(deps) > 3 and deps[0] == port_hostname and deps[2] == macp_hostname and deps[3] == local_port:
                    deps_reve = 1
                elif len(deps) > 3 and deps[0] == macp_hostname and deps[2] == port_hostname:
                    deps_dupl = 1
                    if deps[1] == local_port:
                        port_dupl = 1
                elif len(deps) > 3 and deps[0] == port_hostname and deps[2] == macp_hostname:
                    deps_dupl = 1
            if deps_reve and not deps_skip:
                print('WARNING: reverse dependency found for:')
            elif port_dupl and not deps_skip:
                print('WARNING: duplicate port dependency found for:')
            elif deps_dupl and not deps_skip:
                print('WARNING: duplicate host dependency found for:')

            if not deps_skip:
                print(macp[0] + ' ' + macp_ip + ' ' + macp_hostname + ' port ' + macp[1] + ' ('+local_port+')' + ' found on ' + port_ip + ' ' + port_hostname + ' port ' + port_data[1] + ' (' + str(port_share) + ')')
                macf_f.write(macp[0] + ';' + macp_ip + ';' + macp_hostname + ';' + local_port + ';' + port_ip + ';' + port_hostname + ';' + port_data[1] + ';' + str(port_share) +'\n')

            if port_share == 0 and not deps_skip:
                deps_list += macp_hostname+';'+local_port+';'+port_hostname+';'+port_data[1]+'\n'
                host_deps = ''
                host_deps += 'apply Dependency "switching" to Service {' +'\n'
                host_deps += '  parent_host_name = "' + port_hostname + '"' +'\n'
                host_deps += '  parent_service_name = "' + parent_service + '"' +'\n'
                if deps_reve:
                    host_deps += '  disable_notifications = true' +'\n'
                else:
                    host_deps += '  disable_checks = true' +'\n'
                host_deps += '' +'\n'
                host_deps += '  assign where host.name == "' + macp_hostname + '"' + ' && service.name == "'+local_service+'"''\n'
                host_deps += '}' +'\n'
                if deps_reve:
                    revs_f.write(host_deps)
                elif port_dupl:
                    dups_f.write(host_deps)
                else:
                    deps_f.write(host_deps)
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
        if port_hostname == '':
            port_hostname = port_ip

        deps_skip = 0
        for deps in deps_list.split('\n'):
            deps = deps.split(';')
            if len(deps) > 3 and deps[0] == macp_hostname and deps[2] == port_hostname and deps[3] == port_data[1]:
                deps_skip = 1
                break

        foun_skip = 0
        for foun in foun_list.split('\n'):
            foun = foun.split(';')
            if len(foun) > 2 and foun[0] == macp_hostname and foun[1] == port_hostname and foun[2] == port_data[1]:
                foun_skip = 1
                break

        if macp[0] != prev_maca and not (deps_skip or foun_skip):
            foun_list += macp_hostname+';'+port_hostname+';'+port_data[1]+'\n'
            local_port = ''
            if macp[0] == arpa:
                local_port = 'arp'
            print(macp[0] + ' ' + macp_ip + ' ' + macp_hostname + ' port ' + macp[1] + ' ('+local_port+')' + ' found on ' + port_ip + ' ' + port_hostname + ' port ' + port_data[1] + ' (' + str(port_share) + ')')
            macf_f.write(macp[0] + ';' + macp_ip + ';' + macp_hostname + ';' + local_port + ';' + port_ip + ';' + port_hostname + ';' + port_data[1] + ';' + str(port_share) +'\n')
            prev_maca = macp[0]
    elif macp[1] == 'arp' and port_share > 0:
        print(macp[0] + ' ' + macp_ip + ' port ' + macp[1] + ' not found')
macf_f.close()
deps_f.close()
dups_f.close()
revs_f.close()
