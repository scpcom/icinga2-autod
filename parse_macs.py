#!/usr/bin/env python3
import csv
import os
import re
import sys
from uuid import getnode as get_mac

try:
    import OuiLookup
except ImportError:
    sys.path.append(os.path.join(os.path.dirname(__file__), 'ouilookup'))
    try:
        import OuiLookup
    except ImportError:
        print('WARNING: OuiLookup not available.')
    except SyntaxError:
        print('WARNING: OuiLookup not compatible with this python version.')

h = iter(hex(get_mac())[2:].zfill(12))
my_mac = ":".join(i + next(h) for i in h).upper()
macp_filename = 'discovered_hosts_mac_ports.csv'
macf_filename = macp_filename[:-14] + '_mac_found.csv'
macu_filename = macp_filename[:-14] + '_mac_unknown.csv'
maca_filename = macp_filename[:-14] + '_mac_all.csv'
macd_filename = macp_filename[:-14] + '_dhcp.csv'
deps_filename = macp_filename[:-14] + '_deps.conf'
dups_filename = macp_filename[:-14] + '_deps_dups.conf'
revs_filename = macp_filename[:-14] + '_deps_revs.conf'
arps_filename = macp_filename[:-14] + '_deps_arps.conf'
arpu_filename = macp_filename[:-14] + '_deps_arpu.conf'
lldt_filenames = [f for f in os.listdir('.') if re.match(r'.*_mac_lldp\.csv', f)]
mact_filenames = [f for f in os.listdir('.') if re.match(r'.*_mac_table\.csv', f)]
macp_filenames = [f for f in os.listdir('.') if re.match(r'.*_mac_ports\.csv', f)]

def build_deps_entry(macp_hostname, local_service, port_hostname, parent_service, deps_reve):
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
    return host_deps

def get_mac_vendor(mac, default=''):
    mac_vendor = default
    if mac == '':
        return mac_vendor
    try:
        ouilookup = OuiLookup.OuiLookup(logger_level=OuiLookup.LOGGER_LEVEL_DEFAULT)
        response = ouilookup.query(expression=mac)
    except NameError:
        return mac_vendor
    for item in response:
        for value in item.values():
            mac_vendor = value
            break
        if mac_vendor:
            break
    if mac_vendor is None:
        mac_vendor = default
    return mac_vendor

def read_check_file(check_filename):
    check_reader = list()
    r_code = 1
    try:
        with open(check_filename) as check_file:
            check_reader += list( csv.reader(check_file, delimiter=';') )
            r_code = 0
    except FileNotFoundError:
        check_reader = list()
    n_rows = len(check_reader)
    return r_code, n_rows, check_reader

def write_check_file(check_filename, check_row):
    r_code = 1
    with open(check_filename, 'a') as check_file:
        check_writer = csv.writer(check_file, delimiter=';')
        check_writer.writerow(check_row)
        r_code = 0
    return r_code

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
macu_f = open(macu_filename, 'w')
deps_f = open(deps_filename, 'w')
dups_f = open(dups_filename, 'w')
revs_f = open(revs_filename, 'w')
arps_f = open(arps_filename, 'w')
arpu_f = open(arpu_filename, 'w')
r_code, n_rows, maca_values = read_check_file(maca_filename)
r_code, n_rows, macd_values = read_check_file(macd_filename)
deps_list = ''
foun_list = ''
maca_list = ''
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

    mac_found = 0
    for maca in maca_values:
        if maca[0] == macp[0]:
            mac_found = 1
            break
    for maca in maca_list.split('\n'):
        if maca.startswith(macp[0]):
            mac_found = 1
            break
    if not mac_found:
        #print(macp[0] + ' ' + macp_ip + ' ' + macp_hostname + ' new MAC')
        maca_list += macp[0] + ';' + macp_ip + ';' + macp_hostname + '\n';

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
            elif local_port == 'chassis':
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
            if local_port == '' and not deps_skip:
                print('WARNING: local port not found for:')
            elif deps_reve and not deps_skip:
                print('WARNING: reverse dependency found for:')
            elif port_dupl and not deps_skip:
                print('WARNING: duplicate port dependency found for:')
            elif deps_dupl and not deps_skip:
                print('WARNING: duplicate host dependency found for:')

            if not deps_skip:
                print(macp[0] + ' ' + macp_ip + ' ' + macp_hostname + ' port ' + macp[1] + ' ('+local_port+')' + ' found on ' + port_ip + ' ' + port_hostname + ' port ' + port_data[1] + ' (' + str(port_share) + ')')
                macf_f.write(macp[0] + ';' + macp_ip + ';' + macp_hostname + ';' + local_port + ';' + port_ip + ';' + port_hostname + ';' + port_data[1] + ';' + str(port_share) +'\n')
                deps_list += macp_hostname+';'+local_port+';'+port_hostname+';'+port_data[1]+'\n'

            if port_share == 0 and local_port != '' and not deps_skip:
                host_deps = build_deps_entry(macp_hostname, local_service, port_hostname, parent_service, deps_reve)
                if deps_reve:
                    revs_f.write(host_deps)
                elif port_dupl:
                    dups_f.write(host_deps)
                else:
                    deps_f.write(host_deps)
            prev_maca = macp[0]

    for mact in mact_reader:
        if macp[0] == mact[0] and not macp_ip == mact[2]:
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
                local_service = 'ping4'
                parent_service = 'snmp-int-port'+str(int(port_data[1]))
                host_deps = build_deps_entry(macp_hostname, local_service, port_hostname, parent_service, False)
                if port_share < 3:
                    arps_f.write(host_deps)
                else:
                    arpu_f.write(host_deps)
            print(macp[0] + ' ' + macp_ip + ' ' + macp_hostname + ' port ' + macp[1] + ' ('+local_port+')' + ' found on ' + port_ip + ' ' + port_hostname + ' port ' + port_data[1] + ' (' + str(port_share) + ')')
            macf_f.write(macp[0] + ';' + macp_ip + ';' + macp_hostname + ';' + local_port + ';' + port_ip + ';' + port_hostname + ';' + port_data[1] + ';' + str(port_share) +'\n')
            prev_maca = macp[0]
    elif macp[1] == 'arp' and port_share > 0:
        print(macp[0] + ' ' + macp_ip + ' port ' + macp[1] + ' not found')
macf_f.close()
deps_f.close()
dups_f.close()
revs_f.close()
arps_f.close()
arpu_f.close()
for lldt in lldt_reader:
    found = 0
    for macp in macp_reader:
        if lldt[0] == macp[0]:
            found = 1
            break
    if not found:
        for maca in maca_values:
            if lldt[0] == maca[0]:
                found = 1
                break
    if not found:
        print('Unknown LLD: '+lldt[0])
        macu_f.write(lldt[0] + ';' + 'lld' + ';' + get_mac_vendor(lldt[0]) +'\n')
macu_list = ''
for mact in mact_reader:
    found = 0
    for macp in macp_reader:
        if mact[0] == macp[0]:
            found = 1
            break
    if not found:
        for maca in maca_values:
            if mact[0] == maca[0]:
                found = 1
                break
    if not found:
        if mact[0] == my_mac:
            found = 1
    if not found:
        for macu in macu_list.split('\n'):
            if mact[0] == macu:
                found = 1
    if not found:
        macs = mact[0].replace(':','').upper()
        for macd in macd_values:
            if macs == macd[1].upper():
                found = 1
                break
    if not found:
        macu_list += mact[0] +'\n'
        print('Unknown MAC: '+mact[0])
        macu_f.write(mact[0] + ';' + 'mac' + ';' + get_mac_vendor(mact[0]) +'\n')
macu_f.close()
for maca in maca_list.split('\n'):
    maca = maca.split(';')
    if maca[0] != '':
        print('New MAC: '+' '.join(maca))
        r_code = write_check_file(maca_filename, maca)
