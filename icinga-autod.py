#!/usr/bin/env python3
import util.checkpkg as checkpkg

checkpkg.check(['nmap', 'snmp', 'net-snmp-utils'])

import csv
import os
import sys
import subprocess
import json
import string

try:
    import argparse
except ImportError:
    checkpkg.check(['python-argparse'])

import time
import socket
import util.ianaparse as ianaparse
from util.upnptools import upnp_process_description, upnp_print_schema, upnp_get_service, set_upnp_ns

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

"""
This discovery script will scan a subnet for alive hosts, 
determine some basic information about them,
then create a hosts.conf in the current directory for use in Nagios or Icinga

required Linux packages: python-nmap and nmap

Copyright Wylie Hobbs - 08/28/2015

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

USAGE = './icinga-autod.py -n 192.168.1.0/24'

def build_parser():

    parser = argparse.ArgumentParser(description='Device AutoDiscovery Tool')

    parser.add_argument('-n', '--network', required=True,
        help='Network segment (only /24) to iterate through for live IP addresses in CIDR IPv4 Notation')

    parser.add_argument('-L', '--location', default=None,
        help='Location alias of the network - will be appended to the hosts config (i.e. hosts_location.conf)')

    parser.add_argument('-c', '--communities', default="public,private",
        help='Specify comma-separated list of SNMP communities to iterate through (to override default public,private)')

    parser.add_argument('-d', '--debug', default=False,
        help='Specify comma-separated list of SNMP communities to iterate through (to override default public,private)')

    #The following two arguments have no effect currently
    parser.add_argument('-r', '--reparse-iana', default=False,
        help='Whether icinga-autod should grab a fresh version of the sysObjectIDs from the IANA URL')

    parser.add_argument('-t', '--thorough', default=0,
        help='Thorough scan mode (will take longer) - will try additional SNMP versions/communities to try to gather as much information as possible')

    parser.add_argument('-Z', '--hostzone', default='',
        help='Parent icinga zone of the host endpoints')

    parser.add_argument('-m', '--minimze-tr64', default='',
        help='Do not scan all possible tr64 locations')

    return parser

def main():

    global debug
    global thorough

    parser = build_parser()
    args = parser.parse_args()

    '''Check arguments'''    
    if check_args(args) is False:
        sys.stderr.write("There was a problem validating the arguments supplied. Please check your input and try again. Exiting...\n")
        sys.exit(1)

    if args.debug:
        debug = True
    else:
        debug = False
    if args.thorough:
        thorough = True
    else:
        thorough = False
    
    start_time = time.time()

    cidr = args.network

    location = args.location

    credential = dict()
    credential['version'] = [ '2c', '1' ]
    credential['community'] = args.communities.split(',')

    #Hostname and sysDescr OIDs
    oids = '1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.6.0 1.3.6.1.2.1.1.2.0'

    #Scan the network
    hosts = handle_netscan(cidr)

    all_hosts = {}

    print("Found {0} hosts - gathering more info (can take up to 2 minutes)".format(get_count(hosts)))

    try:
        with open('iana_numbers.json', 'r') as f:
            numbers = json.load(f)
    except Exception as e:
        try:
            numbers = ianaparse.IanaParser().parse()
        except:
            sys.exit("Unable to open iana_numbers.json or read from the URL. Exiting...")

        sys.stderr.write('Unable to open iana_numbers.json, trying URL method. Please wait\n')


    for host in hosts:
        host = str(host)

        '''If your communities/versions vary, modify credentials here. I've used last_octet to do this determination
                octets = host.split('.')
                last_octet = str(octets[3]).strip()
           Otherwise, grab the data
        '''

        hostname = ''
        hostmac = ''

        if ',' in host:
            hostname, host = host.split(',')
        if ';' in host:
            host, hostmac = host.split(';')

        syssnmp = 0
        ret, output, err = exec_command('nmap -sU -p161 {0}'.format(host))
        if ret and err:
            syssnmp = 0
        else:
            syssnmp = parse_nmap_port_scan(output, '161/udp ')

        snmp_timeout = 1
        if syssnmp == 1:
            snmp_timeout = 2

        data = snmpget_by_cl(host, credential, oids, snmp_timeout)

        '''TODO: clean up this logic...'''
        try:
            output = data['output'].split('\n')
            community = data['community']
            snmp_version = data['version']

            hostname = output[0].strip('"')
            sysdesc = output[1].strip('"').strip('\r')
            syslocation = output[-3].strip('"')
            sysobject = output[-2].strip('"') 

        except:
            community = 'unknown'
            snmp_version = ''
            output = ''

            syslocation = ''
            sysdesc = ''
            sysobject = ''

        have_snmp = 0
        if community != '' and  community != 'unknown':
            have_snmp = 1

        if have_snmp == 0 and syssnmp == 1:
            print(host + ' ' + hostname + ' WARNING: SNMP port is open but unable to get data.')

        v_match = vendor_match(numbers, sysobject)

        if v_match:
            vendor = v_match['o'].strip('"')
        else:
            vendor = None

        all_hosts[host] = {
            'community': community, 'snmp_version': snmp_version, 'hostname': hostname, 'hostmac': hostmac, 'sysdesc': sysdesc, 'syslocation': syslocation, 'vendor' : vendor }

        if debug:
            print(host, sysobject, all_hosts[host])

    print("\n")
    print("Discovery took %s seconds" % (time.time() - start_time))
    compile_start = time.time()
    print("Writing data to config file. Please wait")

    outfile = compile_hosts(all_hosts, location, args)
    print("Compile took %s seconds" % (time.time() - compile_start))
    print("Wrote data to "+outfile)

def vendor_match(numbers, sysobject):
    if sysobject:
        #Possible prefixes in sysObjectID OID largely dependent on MIB used
        prefixes = ['SNMPv2-SMI::enterprises.', 'iso.3.6.1.4.1.', '1.3.6.1.4.1.', 'NET-SNMP-MIB::netSnmpAgentOIDs.', 'ccitt.']

        for prefix in prefixes:
            if sysobject.startswith(prefix):
                sysobject = sysobject[len(prefix):]

        values = sysobject.split('.')
        #first value will be the enterprise number
        vendor_num = values[0]

        try:
            vendor_string = numbers[vendor_num]
            return vendor_string

        except Exception as e:
            sys.stderr.write('Unknown sysObjectID prefix encountered - you can add it to the prefix list in vendor_match(), but please report this on GitHub\n{0}'.format(e))
            return False
    else:
        return False

def check_args(args):
    '''Exit if required arguments not specified'''
    '''
    if args.network == None:
        sys.stderr.write("Network and/or location are required arguments! Use -h for help\n")
        sys.exit(1)
    '''
    check_flags = {}
    '''Iterate through specified args and make sure input is valid. TODO: add more flags'''
    try:
        args_items = vars(args).iteritems()
    except AttributeError:
        args_items = vars(args).items()
    for k,v in args_items:
        if k == 'network':
            network = v.split('/')[0]
            if len(network) > 7:
                if is_valid_ipv4_address(network) is False:
                    check_flags['is_valid_ipv4_address'] = False
            else:
                check_flags['is_valid_ipv4_format'] = False

    last_idx = len(check_flags) - 1
    last_key = ''

    '''Find last index key so all the violated flags can be output in the next loop'''
    for idx, key in enumerate(check_flags):
        if idx == last_idx:
            last_key = key

    try:
        check_flags_items = check_flags.iteritems()
    except AttributeError:
        check_flags_items = check_flags.items()
    for flag, val in check_flags_items:
        if val is False:
            sys.stderr.write("Check "+flag+" failed to validate your input.\n")
            if flag == last_key:
                return False

def is_valid_ipv4_address(address):
    '''from http://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python'''
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def get_count(hosts):
    count = len(hosts)
    if count == 0:
        print("No hosts found! Is the network reachable? \nExiting...")
        sys.exit(0)
    else:
        return count

def get_hex_string(data, list):
    roid = '.'.join(data.split('.')[:6])
    rstr = ''
    for l in list:
        s = l.strip('"').strip('\r')
        if s == '':
            continue
        if l == data:
            rstr += s
        elif l.startswith(roid) and rstr != '':
            break
        elif rstr != '':
            rstr += ' '
            rstr += s
    rstr = ': '.join(rstr.split(': ')[1:]).strip('"').strip('\r')
    if ' = Hex-STRING: ' in data:
        nstr = ''
        for h in rstr.split(' '):
            if len(h) == 2:
                h = int(h,16)
                # Todo: Get Mgmt IP after first zero
                # 04 00 04 01 04 AC 10 C0 04 = IP 172.16.192.4
                if h == 0:
                    break
                if chr(h) == '\n':
                    nstr += ' '
                else:
                    nstr += chr(h)
        rstr = nstr.strip('\r')
    return rstr

def get_hex_digits(portid):
    hexd = ''
    sepd = ''
    sepi = 0
    i = 0
    for c in portid:
        i += 1
        if c in ' -:':
            if len(hexd) == 0:
                sepi = i
                continue
            if sepd == '':
                sepd = c
        if sepd == c:
            if not (i - sepi) % 2:
                hexd = ''
                break
            sepi = i
            continue
        elif c not in string.hexdigits:
            break
        hexd += c.upper()
        if len(hexd) % 3 == 2:
            hexd += ':'
    if hexd.endswith(':'):
        hexd = hexd[:-1]
    return hexd

def get_mac_digits(portid):
    macd = get_hex_digits(portid)
    if len(macd) == 17:
        return macd
    return ''

def get_mac_vendor(mac):
    mac_vendor = None
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

def port_str(no):
    global is_dgs3100s2

    if is_dgs3100s2 == "true" and no > 50:
        return '2:'+str(no-50)
    return str(no)

def get_vlan_desc(vlegre, vlunta, vlforb):
    es = vlegre.split(' ')
    us = vlunta.split(' ')
    fs = vlforb.split(' ')
    ed = 'T'
    ud = 'U'
    fd = 'E'
    if len(es) == len(us):
        ix = 0
        px = 1
        fx = px
        prev_t = 255
        for e in es:
          u = us[ix]
          x = '00'
          if ix < len(fs) and len(fs[ix]) == 2:
              x = fs[ix]
          #print(x)
          #print(len(x))
          if len(u) == 2:
            e = int(e, 16)
            u = int(u, 16)
            x = int(x, 16)
            for bit in reversed(range(8)):
                t = 0
                if x & (1 << bit):
                    t = 3
                    #fd += str(px)+',
                elif u & (1 << bit):
                    t = 2
                    #ud += str(px)+','
                elif e & (1 << bit):
                    t = 1
                    #ed += str(px)+','
                if prev_t != t:
                    if px-1 > fx:
                        s = port_str(fx)+'-'+port_str(px-1)+','
                    else:
                        s = port_str(fx)+','
                    if prev_t == 3:
                        fd += s
                    elif prev_t == 2:
                        ud += s
                    elif prev_t == 1:
                        ed += s
                    fx = px
                    prev_t = t
                px+=1
          ix += 1
        if px-1 > fx:
            s = port_str(fx)+'-'+port_str(px-1)+','
        else:
            s = port_str(fx)+','
        if prev_t == 3:
            fd += s
        elif prev_t == 2:
            ud += s
        elif prev_t == 1:
            ed += s
    ed = ed[:-1]
    ud = ud[:-1]
    fd = fd[:-1]
    return ed, ud, fd

def skip_port(ifde, ifty, ifna, ifal):
    port_filter = ['CPU', 'TRK', 'NULL', 'InLoopBack', 'Vlan', 'Console Port', 'Management Port', 'VLAN', '802.1Q Encapsulation', 'Stack Aggregated', 'rif0', 'vlan', 'Internal Interface', 'DEFAULT_VLAN', 'loopback interface', 'stack-port', 'xenbr', 'xapi', 'vlanMgmt', 'fwbr', 'fwln', 'fwpr', 'jsrv', 'Bridge-Aggregation']
    desc_filter = ['IP Interface']
    alias_filter = [' LightWeight Filter', 'QoS Packet Scheduler', 'WiFi Filter Driver', 'Kerneldebugger']
    # IANAifType-MIB
    #   1 other
    #  22 propPointToPointSerial
    #  23 ppp
    #  24 softwareLoopback
    #  53 propVirtual
    #  71 ieee80211
    # 131 tunnel
    # 135 l2vlan
    # 142 ipForward
    # 150 mplsTunnel
    # 161 ieee8023adLag
    # 188 radioMAC
    # 244 wwanPP2
    # 246 ilan
    # 247 pip
    type_filter = [1, 22, 23, 24, 53, 71, 131, 135, 142, 150, 188, 244, 246, 247]

    ifskip = 0
    for prefix in desc_filter:
        if ifde.startswith(prefix):
            ifskip = 1
            break
    for prefix in port_filter:
        if ifna.startswith(prefix):
            ifskip = 1
            break
    for filali in alias_filter:
        if filali in ifal:
            ifskip = 1
            break
    for filtyp in type_filter:
        if ifty == filtyp:
            ifskip = 1
            break
    iltmp = 0
    if ifna.startswith('ae') and len(ifna) < 8:
        iltmp = 2
    elif ifna.startswith('ch') and len(ifna) < 5:
        iltmp = 2
    elif ifna.startswith('me') and len(ifna) < 5:
        iltmp = 2
    elif ifna.startswith('po') and len(ifna) < 5:
        iltmp = 2
    elif ifna.startswith('tap') or ifna.startswith('vif'):
        iltmp = 3
    elif ifna.startswith('bme') or ifna.startswith('vme'):
        iltmp = 3
    elif ifna.startswith('bond') or ifna.startswith('lagg'):
        iltmp = 4
    elif ifna.startswith('vmbr') or ifna.startswith('veth'):
        iltmp = 4
    if iltmp > 0:
        iftmp = ifna[iltmp:].split('.')
        elskip = 1
        for ifelement in iftmp:
            if len(ifelement) > 4:
                elnonum = 0
                for c in ifelement:
                    if c not in '0123456789':
                        elnonum = elnonum + 1
                if elnonum > 1:
                    elskip = 0
        if len(iftmp) > 2:
            elskip = 0
        if elskip:
            ifskip = 1
    return ifskip

def createFolder(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print ('Error: Creating directory. ' +  directory)

def compile_hosts(data, location, args):
    global is_dgs3100s2

    min_tr64_desc_locations = [
        '49000/igddesc.xml',
        '80/upnp/BasicDevice.xml',
    ]
    all_tr64_desc_locations = [
        '49000/igddesc.xml',
        '49000/tr64desc.xml',
        '49000/fboxdesc.xml',
        '37215/tr064dev.xml',
        '49300/description.xml',
        '49152/IGDdevicedesc_brlan0.xml',
        '5000/rootDesc.xml',
        '65530/root.sxml',
        '52869/picsdesc.xml',
        '52881/simplecfg.xml',
        '1900/igd.xml',
        '80/root.sxml',
        '80/upnp/BasicDevice.xml',
        '80/bmlinks/ddf.xml',
        '49152/wps_device.xml',
        '49152/rootdesc1.xml',
        '5200/Printer.xml',
        '8008/ssdp/device-desc.xml',
        '9197/dmr',
        '1401/',
    ]

    hostzone = args.hostzone
    minimze_tr64 = args.minimze_tr64
    altportscan = 1

    mon_hostname = socket.gethostname()
    mon_ip = socket.gethostbyname(mon_hostname)
    grafana_proxmox_url = ""
    if mon_ip != '127.0.0.1':
        grafana_proxmox_url = "http://{0}:{1}/d/kxQQuHRZk/proxmox?orgId=1&refresh=15m&var-server=$name$".format(mon_ip, 3000)

    tr64_desc_locations = all_tr64_desc_locations
    if minimze_tr64:
        tr64_desc_locations = min_tr64_desc_locations

    set_upnp_ns(0)

    if location: 
        loc = location.lower()
        filename = 'hosts_'+loc+'.conf'
    else:
        filename = 'discovered_hosts.conf'

    filedir = filename.replace('.conf', '.d')
    macp_filename = filename.replace('.conf', '_mac_ports.csv')
    mact_filename = filename.replace('.conf', '_mac_table.csv')
    lldt_filename = filename.replace('.conf', '_mac_lldp.csv')
    vlan_filename = filename.replace('.conf', '_vlans.csv')

    f = open(filename, 'w')
    createFolder(filedir)
    macp_f = open(macp_filename, 'w')
    mact_f = open(mact_filename, 'w')
    lldt_f = open(lldt_filename, 'w')
    vlan_f = open(vlan_filename, 'w')

    done_list = ''
    nscp_r_code, nscp_n_rows, nscp_reader = read_check_file('discovered_hosts_nscp.csv')

    try:
        data_items = data.iteritems()
    except AttributeError:
        data_items = data.items()
    for ip, hdata in data_items:
        have_snmp = 0
        if hdata['community'] != '' and  hdata['community'] != 'unknown':
            have_snmp = 1

        hostfqdn = ''
        hostname = hdata['hostname']
        if not hostname:
            hostname = ''
        if hostname == '':
            ret, output, err = exec_command('nslookup {0}'.format(ip))
            if ret and err or not output:
                output = ''
            for line in output.split('\n'):
                if 'name = ' in line:
                    hostname = line.split(' = ')[1]
        if hostname.endswith('.'):
            hostname = hostname[:-1]

        tr64_location = ''
        tr64_control_port = ''
        tr64_control = ''
        tr64_device = None
        prev_tr64_port = '0'
        systr64 = 0
        for tr64_desc_location in tr64_desc_locations:
            tr64_port = tr64_desc_location.split('/')[0]
            if prev_tr64_port != tr64_port:
                prev_tr64_port = tr64_port
                systr64 = 0
                ret, output, err = exec_command('nmap -p{0} {1}'.format(tr64_port, ip))
                if ret and err:
                    systr64 = 0
                else:
                    systr64 = parse_nmap_port_scan(output, '{0}/tcp '.format(tr64_port))
            if not systr64:
                continue
            tr64_location = 'http://'+str(ip)+':'+tr64_desc_location
            set_upnp_ns(0)
            try:
                tr64_device = upnp_process_description(tr64_location)
            except:
                tr64_device = None
            if tr64_device is None:
                set_upnp_ns(1)
                try:
                    tr64_device = upnp_process_description(tr64_location)
                except:
                    tr64_device = None
            if tr64_device is not None:
                break

        hostmac = hdata['hostmac']
        sysvendor = hdata['vendor']
        sysdesc = hdata['sysdesc']
        devdesc = snmpwalk_get_value(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.25.3.2.1.3.1', '')

        if sysvendor == 'Reserved':
            sysvendor = None

        if tr64_device is not None:
            tr64_service = upnp_get_service(tr64_device, 'WANCommonInterfaceConfig:1')
            if tr64_service is not None:
                tr64_control = tr64_service.control_url
                end_of_proto = tr64_control.find('://')
                if end_of_proto > 0:
                    tr64_control = tr64_control[end_of_proto+3:].split('/')
                    if ':' in tr64_control[0]:
                        tr64_control_port = tr64_control[0].split(':')[1]
                    tr64_control = '/' + '/'.join(tr64_control[1:])

            if tr64_device.manufacturer and (sysvendor == '' or not sysvendor):
                sysvendor = tr64_device.manufacturer
            if tr64_device.model_description and sysdesc == '':
                sysdesc = tr64_device.model_description
            elif tr64_device.model_number and sysdesc == '':
                sysdesc = tr64_device.model_number
            if tr64_device.model_name and devdesc == '':
                devdesc = tr64_device.model_name

        if hostmac != '' and not sysvendor:
            sysvendor = get_mac_vendor(hostmac)

        syshttp = 0
        ret, output, err = exec_command('nmap -p80 {0}'.format(ip))
        if ret and err:
            syshttp = 0
        else:
            syshttp = parse_nmap_port_scan(output, '80/tcp ')

        nicName = ''
        if syshttp == 1:
            ret, output, err = exec_command('wget --no-check-certificate -O- http://{0}/'.format(ip))
            if ret and err or not output:
                output = ''
            for line in output.split('\n'):
                if 'Integrated Lights-Out 2' in line or 'Integrated Lights Out 2' in line:
                    if sysdesc == '':
                        sysdesc = 'Integrated Lights-Out 2'
                elif 'Integrated Lights-Out 3' in line or 'Integrated Lights Out 3' in line:
                    if sysdesc == '':
                        sysdesc = 'Integrated Lights-Out 3'
                elif 'nicName="' in line:
                    if nicName == '':
                        nicName = line.split('"')[1]
                elif ' XCP-ng ' in line:
                    if sysdesc == '':
                        sysdesc = 'XCP-ng'
                    elif not 'XCP-ng' in sysdesc:
                        sysdesc += ' XCP-ng'
                elif ' XenServer ' in line:
                    if sysdesc == '':
                        sysdesc = 'XenServer'
                    elif not 'XenServer' in sysdesc:
                        sysdesc += ' XenServer'

        syshttps = 0
        ret, output, err = exec_command('nmap -p443 {0}'.format(ip))
        if ret and err:
            syshttps = 0
        else:
            syshttps = parse_nmap_port_scan(output, '443/tcp ')

        if syshttps == 1:
            ret, output, err = exec_command('nmap --script ssl-enum-ciphers -p443 {0}'.format(ip))
            if ret and err:
                syshttps = 0
            else:
                syshttps = parse_nmap_ssl_scan(output)
            if syshttps < 0:
                print(str(ip) + ' ' + hostname + ' WARNING: HTTPS port is open but only legacy ciphers available.')
                syshttps = 0
            elif not syshttps:
                print(str(ip) + ' ' + hostname + ' WARNING: HTTPS port is open but unable to enum ssl ciphers.')

        action_urls = ""
        if syshttps == 1:
            action_urls += "'https://{0}/' ".format('$address$')
        elif syshttp == 1:
            action_urls += "'http://{0}/' ".format('$address$')

        althttp_ports = [ 1080, 3000, 3128, 8080, 10080 ]
        if thorough:
            for port in althttp_ports:
                althttp = 0
                ret, output, err = exec_command('nmap -p{0} {1}'.format(port, ip))
                if ret and err:
                    althttp = 0
                else:
                    althttp = parse_nmap_port_scan(output, '{0}/tcp '.format(port))
                if althttp:
                    print(str(ip) + ' ' + hostname + ' port '+str(port)+' open')

        althttps_ports = [ 8006, 8007, 8443 ]
        if thorough:
            althttps_ports = [ 1443, 3129, 8006, 8007, 8443, 10443 ]
        if altportscan:
            for port in althttps_ports:
                althttps = 0
                ret, output, err = exec_command('nmap -p{0} {1}'.format(port, ip))
                if ret and err:
                    althttps = 0
                else:
                    althttps = parse_nmap_port_scan(output, '{0}/tcp '.format(port))

                if althttps == 1:
                    ret, output, err = exec_command('nmap --script +ssl-enum-ciphers -p{0} {1}'.format(port, ip))
                    if ret and err:
                        althttps = 0
                    else:
                        althttps = parse_nmap_ssl_scan(output)
                    if althttps < 0:
                        print(str(ip) + ' ' + hostname + ' WARNING: Alt HTTPS port {0} is open but only legacy ciphers available.'.format(port))
                        althttps = 0
                    elif not althttps:
                        print(str(ip) + ' ' + hostname + ' WARNING: Alt HTTPS port {0} is open but unable to enum ssl ciphers.'.format(port))

                if althttps == 1:
                    action_urls += "'https://{0}:{1}/' ".format('$address$', port)
                    # add grafana link for proxmox dashboard
                    if port == 8006 and grafana_proxmox_url != "":
                        action_urls += "'{0}' ".format(grafana_proxmox_url)
                    if port == 8006 or port == 8007:
                        if sysdesc == '':
                            sysdesc = 'Proxmox'
                        elif not 'Proxmox' in sysdesc:
                            sysdesc += ' Proxmox'

        if action_urls.endswith(' '):
            action_urls = action_urls[:-1]
        if action_urls.startswith("'") and action_urls.endswith("'") and len(action_urls) > 2:
            if not "'" in action_urls[1:-1]:
                action_urls = action_urls[1:-1]

        hostvars = compile_hvars(sysdesc, devdesc)
        hostlocation = location
        if hdata['syslocation'] != '':
            hostlocation = hdata['syslocation']

        if 'Integrated Lights-Out' in sysdesc and nicName != '' and hostname == '':
            hostname = nicName
        if hostname == '':
            hostname = ip
        else:
            hostfqdn = hostname
            hostname = hostname.split('.')[0]
            if hostfqdn == hostname:
                hostfqdn = ''

        if tr64_device is None:
            sysupnp = 0
            ret, output, err = exec_command('nmap -sU -p1900 {0}'.format(ip))
            if ret and err:
                sysupnp = 0
            else:
                sysupnp = parse_nmap_port_scan(output, '1900/udp ')

            if sysupnp == 1:
                print(str(ip) + ' ' + hostname + ' WARNING: UPnP port is open but unable to get data.')

        # .3.6.1.2.1.2.2.1.2     ifDescr
        # .3.6.1.2.1.2.2.1.3     ifType
        # .3.6.1.2.1.2.2.1.6     ifPhysAddress
        # .3.6.1.2.1.2.2.1.7     ifAdminStatus
        # .3.6.1.2.1.2.2.1.8     ifOperStatus
        # .3.6.1.2.1.31.1.1.1.1  ifName
        # .3.6.1.2.1.31.1.1.1.18 ifAlias
        iffirst = 999999
        ifcount = 0
        ifentries = 0
        is_comware = "false"
        is_esxg = "false"
        is_s1700 = "false"
        is_sg300 = "false"
        is_jex = "false"
        is_jexge0 = "false"
        is_jexge1 = "false"
        is_jexxe0 = "false"
        is_jexxe1 = "false"
        is_hp1810v2 = "false"
        is_des1210 = "false"
        is_dgs3100 = "false"
        is_dgs3100s1 = "false"
        is_dgs3100s2 = "false"
        is_dgs3100s3 = "false"
        snmp_interface_ifalias = "false"

        desc_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.2.2.1.2')
        type_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.2.2.1.3')
        phys_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.2.2.1.6')
        admi_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.2.2.1.7')
        oper_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.2.2.1.8')
        name_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.31.1.1.1.1')
        alias_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.31.1.1.1.18')

        if len(name_output) > 0:
            for line in name_output:
                if '.3.6.1.2.1.31.1.1.1.1.' in line:
                    line = '.'.join(line.split('.')[11:])
                    ifno = int(line.split(' ') [0])
                    ifna = ': '.join(line.split(': ')[1:]).strip('"')

                    ifal = ''
                    for alias in alias_output:
                        if '.3.6.1.2.1.31.1.1.1.18.'+str(ifno)+' ' in alias:
                            alias = '.'.join(alias.split('.')[11:])
                            ifal = ': '.join(alias.split(': ')[1:]).strip('"')
                    ifde = ''
                    for desc in desc_output:
                        if '.3.6.1.2.1.2.2.1.2.'+str(ifno)+' ' in desc:
                            desc = '.'.join(desc.split('.')[10:])
                            ifde = ': '.join(desc.split(': ')[1:]).strip('"')
                    ifty = 0
                    for type in type_output:
                        if '.3.6.1.2.1.2.2.1.3.'+str(ifno)+' ' in type:
                            type = '.'.join(type.split('.')[10:])
                            ifty = int(': '.join(type.split(': ')[1:]).strip('"'))
                    #print(str(ifno)+';'+str(ifty)+';'+ifna+';'+ifde+';'+ifal)

                    ifskip = skip_port(ifde, ifty, ifna, ifal)

                    if ifskip == 0 and ifno < iffirst:
                        iffirst = ifno
                    if ifskip == 0 and ifno > ifcount:
                        ifcount = ifno
                        ifentries = ifentries + 1
                        #print(str(ifno)+';'+str(ifty)+';'+ifna+';'+ifde+';'+ifal)
                    if ifna.startswith('GigabitEthernet1/0/'):
                        is_comware = "true"
                    if ifna.startswith('0/'):
                        is_esxg = "true"
                    if ifna.startswith('1/') and ifde.startswith('Huawei S'):
                        is_s1700 = "true"
                    if ifna.startswith('gi') and ifde.startswith('gigabitethernet'):
                        is_sg300 = "true"
                    if ifna.startswith('ge-0/0/'):
                        is_jex = "true"
                        is_jexge0 = "true"
                    if ifna.startswith('ge-1/0/'):
                        is_jex = "true"
                        is_jexge1 = "true"
                    if ifna.startswith('xe-0/0/'):
                        is_jex = "true"
                        is_jexxe0 = "true"
                    if ifna.startswith('xe-1/0/'):
                        is_jex = "true"
                        is_jexxe1 = "true"
                    if ifna.startswith('Port  '):
                        is_hp1810v2 = "true"
                    if ifna.startswith('Slot0/'):
                        is_des1210 = "true"
                    if ifna.startswith('1:'):
                        is_dgs3100 = "true"
                        is_dgs3100s1 = "true"
                    if ifna.startswith('2:'):
                        is_dgs3100 = "true"
                        is_dgs3100s2 = "true"
                    if ifna.startswith('3:'):
                        is_dgs3100 = "true"
                        is_dgs3100s3 = "true"
                    if ifde.startswith('Port #') and ifde == 'Port #'+ifal:
                        snmp_interface_ifalias = "true"

        linevars = hostvars.split('\n')
        agent_services = ''
        is_switch = "false"
        for line in linevars:
            if 'vars.agent_services = ' in line:
                agent_services = line.split(' = ')[1].strip('"')
            if 'vars.network_switch = ' in line:
                is_switch = line.split(' = ')[1].strip('"')

        if (is_comware == "true" or is_s1700 == "true" or is_hp1810v2 == "true") and is_switch != "true":
            is_switch = "true"
            hostvars += 'vars.network_switch = "' + is_switch + '"' +'\n  '

        fix_portno = 0
        if is_dgs3100 == "true":
            fix_portno = 1
        if ifcount > 0 and not is_jex == "true":
            if iffirst > 1 and iffirst < ifcount:
                fix_portno = 1

        fix_mactno = 0
        if is_dgs3100 == "true" or is_sg300 == "true":
            fix_mactno = 1

        fix_lldtno = fix_mactno

        chassisid = snmpwalk_get_value(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.17.1.1.0', '')
        if chassisid != '':
                chassisid = ':'.join(chassisid.split(' ')[:-1])

        if hdata['hostmac'] != '':
            #print(str(ip) + ' ' + hdata['hostname'] + ' got Host MAC')
            macp_f.write(hdata['hostmac'] + ';' + 'arp' + ';' + str(ip) + ';' + hdata['hostname'] + ';' + 'arp' + ';' + '' + ';' + is_switch +'\n')

        portcount = 0

        if len(phys_output) > 0:
            print(str(ip) + ' ' + hdata['hostname'] + ' got Port IDs')
            if chassisid != '':
                macp_f.write(chassisid + ';' + 'chassis' + ';' + str(ip) + ';' + hdata['hostname'] + ';' + 'chassis' + ';' + '' + ';' + is_switch +'\n')
            for line in phys_output:
                if '.3.6.1.2.1.2.2.1.6.' in line:
                    line = '.'.join(line.split('.')[10:])
                    #line = line.split('.')[-1]
                    ifno = int(line.split(' = ')[0])
                    maca = ': '.join(line.split(': ')[1:]).strip('"')
                    if maca.endswith(' RAS'):
                        maca = ''
                    maca = ':'.join(maca.split(' ')[:-1])
                    if maca.startswith('00:00:00:00:00:00'):
                        maca = ''

                    ifna = ''
                    for name in name_output:
                        if '.3.6.1.2.1.31.1.1.1.1.'+str(ifno)+' ' in name:
                            name = '.'.join(name.split('.')[11:])
                            ifna = ': '.join(name.split(': ')[1:]).strip('"')

                    ifal = ''
                    for alias in alias_output:
                        if '.3.6.1.2.1.31.1.1.1.18.'+str(ifno)+' ' in alias:
                            alias = '.'.join(alias.split('.')[11:])
                            ifal = ': '.join(alias.split(': ')[1:]).strip('"')
                    ifde = ''
                    for desc in desc_output:
                        if '.3.6.1.2.1.2.2.1.2.'+str(ifno)+' ' in desc:
                            desc = '.'.join(desc.split('.')[10:])
                            ifde = ': '.join(desc.split(': ')[1:]).strip('"')

                    ifty = 0
                    for type in type_output:
                        if '.3.6.1.2.1.2.2.1.3.'+str(ifno)+' ' in type:
                            type = '.'.join(type.split('.')[10:])
                            ifty = int(': '.join(type.split(': ')[1:]).strip('"'))

                    ifad = 0
                    for admi in admi_output:
                        if '.3.6.1.2.1.2.2.1.7.'+str(ifno)+' ' in admi:
                            admi = '.'.join(admi.split('.')[10:])
                            ifad = int(': '.join(admi.split(': ')[1:]).strip('"'))

                    ifop = 0
                    for oper in oper_output:
                        if '.3.6.1.2.1.2.2.1.8.'+str(ifno)+' ' in oper:
                            oper = '.'.join(oper.split('.')[10:])
                            ifop = int(': '.join(oper.split(': ')[1:]).strip('"'))

                    ifskip = skip_port(ifde, ifty, ifna, ifal)

                    if fix_portno:
                        if ifno >= iffirst:
                            ifno = ifno+1-iffirst
                        else:
                            ifno = ifno+1+ifcount+1-iffirst

                    if maca and maca != '':
                        if ifna == '':
                            ifna = ifde
                        if ifentries < 9 and ifad == 1 and ifop == 1 and not ifskip:
                            hostvars += 'vars.snmp_interfaces["snmp-int-port'+str(ifno)+'"] = {' +'\n  '
                            hostvars += '  snmp_interface = "'+ifna+'"' +'\n  '
                            if ifal != '':
                                hostvars += '  snmp_interface_label = "'+ifal+'"' +'\n  '
                            else:
                                hostvars += '  snmp_interface_label = "'+ifna+'"' +'\n  '
                            hostvars += '}' +'\n  '
                        ifno = str(ifno)
                        if int(ifno) < 10:
                            ifno = '0'+ifno
                        portcount = portcount + 1
                        macp_f.write(maca + ';' + ifno + ';' + str(ip) + ';' + hdata['hostname'] + ';' + ifna + ';' + ifal + ';' + is_switch +'\n')

        have_mact = 0
        output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.17.7.1.2.2.1.2')

        if len(output) > 0:
            print(str(ip) + ' ' + hdata['hostname'] + ' got MAC Table')
            for line in output:
                if '.3.6.1.2.1.17.7.1.2.2.1.2.' in line:
                    ifno = int(': '.join(line.split(': ')[1:]).strip('"'))
                    line = line.split(' = ')[0]
                    line = line.split('.')[14:]
                    if fix_mactno:
                        if ifno >= iffirst:
                            ifno = ifno+1-iffirst
                        else:
                            ifno = ifno+1+ifcount+1-iffirst
                    ifno = str(ifno)
                    if int(ifno) < 10:
                        ifno = '0'+ifno
                    maca = ''
                    for c in line:
                        if maca != '':
                             maca = maca + ':'
                        maca = maca + '{:02X}'.format(int(c))
                    have_mact = 1
                    mact_f.write(maca + ';' + ifno + ';' + str(ip) + ';' + hdata['hostname'] +'\n')

        if have_mact == 0:
            output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.17.4.3.1.2')
        else:
            output = list()

        if len(output) > 0:
            print(str(ip) + ' ' + hdata['hostname'] + ' got MAC Table')
            for line in output:
                if '.3.6.1.2.1.17.4.3.1.2.' in line:
                    ifno = int(': '.join(line.split(': ')[1:]).strip('"'))
                    line = line.split(' = ')[0]
                    line = line.split('.')[11:]
                    if fix_mactno:
                        if ifno >= iffirst:
                            ifno = ifno+1-iffirst
                        else:
                            ifno = ifno+1+ifcount+1-iffirst
                    ifno = str(ifno)
                    if int(ifno) < 10:
                        ifno = '0'+ifno
                    maca = ''
                    for c in line:
                        if maca != '':
                             maca = maca + ':'
                        maca = maca + '{:02X}'.format(int(c))
                    mact_f.write(maca + ';' + ifno + ';' + str(ip) + ';' + hdata['hostname'] +'\n')

        have_lldt = 0
        output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.0.8802.1.1.2.1.4.1.1.5')

        if len(output) > 0:
            if '.0.8802.1.1.2.1.4.1.1.5.' in output[0]:
                print(str(ip) + ' ' + hdata['hostname'] + ' got LLDP Table')
                rpid_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.0.8802.1.1.2.1.4.1.1.7')
                rpde_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.0.8802.1.1.2.1.4.1.1.8')
                rsid_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.0.8802.1.1.2.1.4.1.1.9')
                rsde_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.0.8802.1.1.2.1.4.1.1.10')
                rsma_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.0.8802.1.1.2.1.4.2.1')

            for line in output:
                if '.0.8802.1.1.2.1.4.1.1.5.' in line:
                    ifid = '.'.join(line.split('.')[11:14]).split(' = ')[0]
                    ifno = int(line.split('.')[12:][0])
                    line = '.'.join(line.split('.')[13:])
                    ifnr = line.split(' = ')[0]
                    ifrpid = ''
                    for rpid in rpid_output:
                        if '.0.8802.1.1.2.1.4.1.1.7.'+ifid+' ' in rpid:
                            ifrpid = ': '.join(rpid.split(': ')[1:]).strip('"')
                            if ' = Hex-STRING: ' in rpid:
                                ifrpid = ':'.join(ifrpid.split(' '))
                                if ifrpid.endswith(':'):
                                    ifrpid = ifrpid[:-1]
                            break
                    ifrpde = ''
                    for rpde in rpde_output:
                        if '.0.8802.1.1.2.1.4.1.1.8.'+ifid+' ' in rpde:
                            ifrpde = get_hex_string(rpde, rpde_output)
                            break
                    ifrsid = ''
                    for rsid in rsid_output:
                        if '.0.8802.1.1.2.1.4.1.1.9.'+ifid+' ' in rsid:
                            ifrsid = get_hex_string(rsid, rsid_output)
                            break
                    ifrsde = ''
                    for rsde in rsde_output:
                        if '.0.8802.1.1.2.1.4.1.1.10.'+ifid+' ' in rsde:
                            ifrsde = get_hex_string(rsde, rsde_output)
                            break
                    ifrsma = ''
                    for rsma in rsma_output:
                        if '.0.8802.1.1.2.1.4.2.1.1.'+ifid+'.' in rsma or \
                           '.0.8802.1.1.2.1.4.2.1.2.'+ifid+'.' in rsma or \
                           '.0.8802.1.1.2.1.4.2.1.3.'+ifid+'.' in rsma or \
                           '.0.8802.1.1.2.1.4.2.1.4.'+ifid+'.' in rsma or \
                           '.0.8802.1.1.2.1.4.2.1.5.'+ifid+'.' in rsma:
                            rsmt = '.'.join(rsma.split('.')[14:16])
                            if rsmt == '1.4':
                                ifrsma = '.'.join(rsma.split('.')[16:]).split(' = ')[0]
                                break
                            elif rsmt == '2.16':
                                ifrsma = ''
                                for o in rsma.split(' = ')[0].split('.')[16:]:
                                    ifrsma += '%.2x' % int(o)
                                    if len(ifrsma) % 5 == 4:
                                        ifrsma += ':'
                                if ifrsma.endswith(':'):
                                    ifrsma = ifrsma[:-1]
                                #break
                            else:
                                print('Unknown lldpRemManAddrSubtype: '+rsmt+';'+ifrsma)
                    if fix_lldtno:
                        if ifno >= iffirst:
                            ifno = ifno+1-iffirst
                        else:
                            ifno = ifno+1+ifcount+1-iffirst
                    ifno = str(ifno)
                    if int(ifno) < 10:
                        ifno = '0'+ifno
                    if int(ifnr) < 10:
                        ifnr = '0'+ifnr
                    maca = ': '.join(line.split(': ')[1:]).strip('"')
                    maci = get_mac_digits(maca)
                    if maci == '':
                        maci = get_mac_digits(ifrpid)
                    if maci == '':
                        maci = get_hex_digits(maca)
                    if len(maci) > 10:
                        maca = maci

                    #print(ifno+';'+ifnr+';'+maca)
                    have_lldt = 1
                    lldt_f.write(maca + ';' + ifno + ';' + ifnr+';' + str(ip) + ';' + hdata['hostname'] + ';' + ifrpid + ';' + ifrpde + ';' + ifrsid + ';' + ifrsde + ';' + ifrsma + ';' + is_switch +'\n')

        output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.17.7.1.4.3.1.1')
        if len(output) > 0:
            if '.3.6.1.2.1.17.7.1.4.3.1.1.' in output[0]:
                print(str(ip) + ' ' + hdata['hostname'] + ' got VLAN Table')
                egre_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.17.7.1.4.3.1.2')
                forb_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.17.7.1.4.3.1.3')
                unta_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.17.7.1.4.3.1.4')
            for line in output:
                if '.3.6.1.2.1.17.7.1.4.3.1.1.' in line:
                    line = '.'.join(line.split('.')[13:])
                    vlnr = line.split(' = ')[0]
                    vlna = ': '.join(line.split(': ')[1:]).strip('"')
                    vlegre = ''
                    for egre in egre_output:
                        if '.3.6.1.2.1.17.7.1.4.3.1.2.'+vlnr+' ' in egre:
                            vlegre = ': '.join(egre.split(': ')[1:]).strip('"')
                            break
                    vlforb = ''
                    for forb in forb_output:
                        if '.3.6.1.2.1.17.7.1.4.3.1.3.'+vlnr+' ' in forb:
                            vlforb = ': '.join(forb.split(': ')[1:]).strip('"')
                            break
                    vlunta = ''
                    for unta in unta_output:
                        if '.3.6.1.2.1.17.7.1.4.3.1.4.'+vlnr+' ' in unta:
                            vlunta = ': '.join(unta.split(': ')[1:]).strip('"')
                            break
                    ed, ud, fd = get_vlan_desc(vlegre, vlunta, vlforb)
                    #print(vlnr+';'+vlna+';'+vlegre+';'+vlforb+';'+vlunta)
                    vlan_f.write(vlnr+';'+vlna+';'+vlegre+';'+vlforb+';'+ vlunta+';' + str(ip) + ';' + hdata['hostname']+';'+ed+';'+ud +'\n')

        snmp_load_type = ""
        if snmpwalk_tree_valid(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.25.3.3.1.2'):
            snmp_load_type = "stand"
        if (snmpwalk_tree_valid(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.25.3.3.1.1') and
            snmpwalk_tree_valid(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.4.1.2021.10.1.2')):
            snmp_load_type = "netsl"

        snmp_is_netsnmp = "false"
        if snmpwalk_tree_valid(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.4.1.2021.4.6'):
            snmp_is_netsnmp = "true"

        snmp_is_hp = "false"
        if snmpwalk_tree_valid(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.4.1.11.2.14.11.5.1.1.2.2.1.1.6'):
            snmp_is_hp = "true"

        snmp_interface_ifname = "false"
        snmp_interface_64bit = "false"
        snmp_interface_speed64bit = "false"
        snmp_interface_perf = "true"
        snmp_interface_bits_bytes = "true"
        if len(name_output) > 0:
            snmp_interface_ifname = "true"
        if snmpwalk_tree_valid(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.31.1.1.1.10'):
            snmp_interface_64bit = "true"
        elif snmpwalk_tree_valid(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.31.1.1.1.15'):
            snmp_interface_speed64bit = "true"
        elif not snmpwalk_tree_valid(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.2.2.1.16'):
            snmp_interface_perf = "false"
            snmp_interface_bits_bytes = "false"

        type_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.25.2.3.1.2')
        desc_output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.25.2.3.1.3')

        snmp_storage_mem_name=''
        snmp_storage_swap_name=''
        snmp_storage_disk_name=''
        snmp_storage_fs_name=''
        if len(desc_output) > 0:
            for line in desc_output:
                if '.3.6.1.2.1.25.2.3.1.3.' in line:
                    line = '.'.join(line.split('.')[11:])
                    stno = int(line.split(' ') [0])
                    stna = ': '.join(line.split(': ')[1:]).strip('"')

                    #if stna.startswith('MALLOC: ') or stna.startswith('UMA: '):
                    #    continue
                    if stna.startswith('devfs: ') or stna.startswith('procfs: '):
                        continue

                    stty = 0
                    for type in type_output:
                        if '.3.6.1.2.1.25.2.3.1.2.'+str(stno)+' ' in type:
                            type = '.'.join(type.split('.')[11:])
                            if '.3.6.1.2.1.25.2.1.' in type:
                                type = ': '.join(type.split(': ')[1:]).strip('"')
                                stty=int(type.split('.')[-1:][0])
                            elif '.3.6.1.2.1.25.3.9.' in type:
                                stty=255
                    if ':\\\\ Label:' in stna:
                        stna = stna.split(' Label:')[0]
                        stna = '\\\\'.join(stna.split('\\'))
                    #print(str(stno)+';'+str(stty)+';'+stna)
                    if stty == 2 and snmp_storage_mem_name == '':
                        snmp_storage_mem_name=stna
                    elif stty == 3 and snmp_storage_swap_name == '':
                        snmp_storage_swap_name=stna
                    elif stty == 4 and snmp_storage_disk_name == '' or stna == '/':
                        snmp_storage_disk_name=stna
                    elif stty == 255 and snmp_storage_fs_name == '' or stna == '/':
                        snmp_storage_fs_name=stna

        #print(str(ifcount) + ' interfaces')
        if is_comware == "true":
            hostvars += 'vars.network_comware = "' + is_comware + '"' +'\n  '
        if is_esxg == "true":
            hostvars += 'vars.network_esxg = "' + is_esxg + '"' +'\n  '
        if is_s1700 == "true":
            hostvars += 'vars.network_s1700 = "' + is_s1700 + '"' +'\n  '
        if is_sg300 == "true":
            hostvars += 'vars.network_sg300 = "' + is_sg300 + '"' +'\n  '
        if is_jex == "true":
            hostvars += 'vars.network_jex = "' + is_jex + '"' +'\n  '
        if is_jexge0 == "true":
            hostvars += 'vars.network_jexge0 = "' + is_jexge0 + '"' +'\n  '
        if is_jexge1 == "true":
            hostvars += 'vars.network_jexge1 = "' + is_jexge1 + '"' +'\n  '
        if is_jexxe0 == "true":
            hostvars += 'vars.network_jexxe0 = "' + is_jexxe0 + '"' +'\n  '
        if is_jexxe1 == "true":
            hostvars += 'vars.network_jexxe1 = "' + is_jexxe1 + '"' +'\n  '
        if is_hp1810v2 == "true":
            hostvars += 'vars.network_hp1810v2 = "' + is_hp1810v2 + '"' +'\n  '
        if is_des1210 == "true":
            hostvars += 'vars.network_des1210 = "' + is_des1210 + '"' +'\n  '
        if is_dgs3100 == "true":
            hostvars += 'vars.network_dgs3100 = "' + is_dgs3100 + '"' +'\n  '
        if is_dgs3100s1 == "true":
            hostvars += 'vars.network_dgs3100s1 = "' + is_dgs3100s1 + '"' +'\n  '
        if is_dgs3100s2 == "true":
            hostvars += 'vars.network_dgs3100s2 = "' + is_dgs3100s2 + '"' +'\n  '
        if is_dgs3100s3 == "true":
            hostvars += 'vars.network_dgs3100s3 = "' + is_dgs3100s3 + '"' +'\n  '
        if ifcount > 0:
            if iffirst < ifcount:
                ifcount = ifcount - iffirst + 1
            hostvars += 'vars.network_ports = ' + str(ifentries) +'\n  '
        if have_snmp:
            hostvars += 'vars.snmp_community = "' + hdata['community'] + '"' +'\n  '
            hostvars += 'vars.snmp_version = "' + hdata['snmp_version'] + '"' +'\n  '
            if hdata['snmp_version'] == '2c':
                hostvars += 'vars.snmp_v2 = "' 'true' + '"' +'\n  '

        if have_snmp:
            if snmp_interface_ifalias == "true":
                hostvars += 'vars.snmp_interface_ifalias = ' + snmp_interface_ifalias +'\n  '
            else:
                hostvars += 'vars.snmp_interface_ifname = ' + snmp_interface_ifname +'\n  '
        if snmp_interface_64bit == "true":
            hostvars += 'vars.snmp_interface_64bit = ' + snmp_interface_64bit +'\n  '
        if snmp_interface_speed64bit == "true":
            hostvars += 'vars.snmp_interface_speed64bit = ' + snmp_interface_speed64bit +'\n  '
        if snmp_interface_perf == "false" and have_snmp == 1:
            hostvars += 'vars.snmp_interface_perf = ' + snmp_interface_perf +'\n  '
        if snmp_interface_bits_bytes == "false" and have_snmp == 1:
            hostvars += 'vars.snmp_interface_bits_bytes = ' + snmp_interface_bits_bytes +'\n  '

        if snmp_load_type != '':
            hostvars += 'vars.snmp_load_type = "' + snmp_load_type + '"' +'\n  '
        if snmp_is_netsnmp == "true":
            hostvars += 'vars.snmp_is_netsnmp = "' + snmp_is_netsnmp + '"' +'\n  '
        if snmp_is_hp == "true":
            hostvars += 'vars.snmp_is_hp = "' + snmp_is_hp + '"' +'\n  '
        if snmp_storage_mem_name != '' and snmp_is_netsnmp == "false" and snmp_is_hp == "false":
             snmp_storage_mem_name = '^'+snmp_storage_mem_name+'$$'
             hostvars += 'vars.snmp_storage_mem_name = "' + snmp_storage_mem_name + '"' +'\n  '
        if snmp_storage_swap_name != '' and snmp_is_netsnmp == "false" and snmp_is_hp == "false":
             hostvars += 'vars.snmp_storage_swap_name = "' + snmp_storage_swap_name + '"' +'\n  '
        if snmp_storage_disk_name != '':
             if snmp_storage_disk_name.startswith('/'):
                 snmp_storage_disk_name = '^'+snmp_storage_disk_name+'$$'
             hostvars += 'vars.snmp_storage_disk_name = "' + snmp_storage_disk_name + '"' +'\n  '
        elif snmp_storage_fs_name != '':
             if snmp_storage_fs_name.startswith('/'):
                 snmp_storage_fs_name = '^'+snmp_storage_fs_name+'$$'
             hostvars += 'vars.snmp_storage_fs_name = "' + snmp_storage_fs_name + '"' +'\n  '
        if tr64_device is not None:
              tr64_location = tr64_location.split(':')[-1].split('/')
              if tr64_control_port != '':
                  hostvars += 'vars.tr64_port = ' + tr64_control_port +'\n  '
                  hostvars += 'vars.tr64_desc_port = ' + tr64_location[0] +'\n  '
              else:
                  hostvars += 'vars.tr64_port = ' + tr64_location[0] +'\n  '
              hostvars += 'vars.tr64_desc_location = "' + '/' + '/'.join(tr64_location[1:]) + '"' +'\n  '
              if tr64_control != '':
                  hostvars += 'vars.tr64_wancmnifc_control_url = "' + tr64_control + '"' +'\n  '
        nscp_pass = ''
        for nscp_row in nscp_reader:
            if len(nscp_row) > 1:
                if nscp_row[0] == str(ip):
                    nscp_pass = nscp_row[1]
        if nscp_pass != '':
             hostvars += 'vars.nscp_password = "' + nscp_pass + '"' +'\n  '
        if hdata['hostmac'] != '':
            hostvars += 'vars.mac_address = "' + hdata['hostmac'] + '"' +'\n  '
        zone_entry = ''
        if agent_services == 'true' and hostfqdn == '' and hostzone != '':
            if hostname != ip and '.' in hostzone:
                hostfqdn = hostname + '.' + '.'.join(hostzone.split('.')[1:])
        if agent_services == 'true' and hostfqdn != '' and hostzone != '':
            hostvars += 'vars.client_endpoint = "' + hostfqdn + '"' +'\n  '
            if hostfqdn != hostzone:
                zone_entry = build_zone_entry(hostfqdn, hostzone)
        hdata['action_urls'] = action_urls
        hdata['syshttp'] = syshttp
        hdata['syshttps'] = syshttps
        host_entry = zone_entry + build_host_entry(hostname, str(ip), hostlocation, sysvendor, str(hostvars), hdata)

        if hdata['hostmac'] != '':
            done_found = 0
            done_multi = 0
            for done in done_list.split('\n'):
                done = done.split(';')
                if len(done) > 2 and done[0] == hostmac:
                    if done[1] == str(ip):
                        done_found = 1
                        break
                    else:
                        print(str(ip) + ' ' + hostname + ' WARNING: found same MAC address on ' + done[1])
                        done_multi = 1

            if not done_found:
                done_list += hostmac+';'+str(ip)+';'+hostname+'\n'

            host_filename = filedir + '/' + 'h-' + hdata['hostmac'].replace(':', '')
            if done_multi:
                 host_filename += '-'+str(ip)
            host_filename += '.conf'
            host_f = open(host_filename, 'w')
            host_f.write(host_entry)
            host_f.close()
        else:
            f.write(host_entry)

    f.close()
    macp_f.close()
    mact_f.close()
    lldt_f.close()
    vlan_f.close()

    return filename

def build_zone_entry(hostfqdn, hostzone):
    zone_entry = ( 'object Endpoint "%s" {\n'
                   '}\n'
                   '\n'
                   'object Zone "%s" {\n'
                   '        endpoints = [ "%s" ]\n'
                   '        parent = "%s"\n'
                   '}\n'
                   '\n'
                 ) % (hostfqdn, hostfqdn, hostfqdn, hostzone)

    return zone_entry

def build_host_entry(hostname, ip, location, vendor, hostvars, hdata):
    icingaweb2_public = '/usr/share/icingaweb2/public'
    icon_filenames = (
        'custom/%s.png',
        'custom/%s.ico',
        'custom/%s.gif',
        'img/icons/%s.png',
        'img/icons/%s.ico',
        'img/icons/%s.gif',
    )
    icon_descriptors = {
        'HP 1810': 'hp',
        'OfficeConnect': 'hpe',
        'ProCurve': 'hp',
        'PROCURVE': 'hp',
        'Juniper Networks': 'juniper-ex',
        'EdgeSwitch': 'ubiquiti-em',
        'FRITZ!': 'fritz',
        'iDRAC9': 'idrac-9',
        'Integrated Dell Remote Access Controller 9': 'idrac-9',
        'iLO 2': 'ilo-2',
        'Integrated Lights-Out 2': 'ilo-2',
        'iLO 3': 'ilo-4',
        'Integrated Lights-Out 3': 'ilo-4',
        'iLO 4': 'ilo-4',
        'Integrated Lights-Out 4': 'ilo-4',
        'iLO 5': 'ilo-4',
        'Integrated Lights-Out 5': 'ilo-4',
        'SEH myUTN': 'seh-technology',
        'pfSense': 'pfsense',
        'FreeBSD': 'freebsd',
        'Proxmox': 'proxmox',
        'XCP-ng': 'xcp-ng',
        'XenServer': 'xs',
        'Linux': 'tux',
        'Windows': 'win',
    }
    icon_vendors = {
        '3Com': '3com',
        'ciscoSystems': 'cisco',
        'Cisco Systems': 'cisco',
        'Dell Inc': 'dell',
        'D-Link Systems': 'dlink',
    }
    host_entry = ( 'object Host "%s" {\n'
                   '  import "generic-host"\n'
                 ) % (hostname)

    linevars = hostvars.split('\n')
    sysdesc = ""
    sysos = ""
    sysep = ""
    is_comware = "false"
    is_esxg = "false"
    is_s1700 = "false"
    is_sg300 = "false"
    is_jex = "false"
    is_jexge0 = "false"
    is_jexge1 = "false"
    is_jexxe0 = "false"
    is_jexxe1 = "false"
    is_hp1810v2 = "false"
    is_des1210 = "false"
    is_dgs3100 = "false"
    is_dgs3100s1 = "false"
    is_dgs3100s2 = "false"
    is_dgs3100s3 = "false"
    is_switch = "false"
    ifcount = 0
    for line in linevars:
        if 'vars.description = ' in line:
            sysdesc = line.split(' = ')[1].strip('"')
        if 'vars.os = ' in line:
            sysos = line.split(' = ')[1].strip('"')
        if 'vars.client_endpoint = ' in line:
            sysep = line.split(' = ')[1].strip('"')
        if 'vars.network_comware = ' in line:
            is_comware = line.split(' = ')[1].strip('"')
        if 'vars.network_esxg = ' in line:
            is_esxg = line.split(' = ')[1].strip('"')
        if 'vars.network_s1700 = ' in line:
            is_s1700 = line.split(' = ')[1].strip('"')
        if 'vars.network_sg300 = ' in line:
            is_sg300 = line.split(' = ')[1].strip('"')
        if 'vars.network_jex = ' in line:
            is_jex = line.split(' = ')[1].strip('"')
        if 'vars.network_jexge0 = ' in line:
            is_jexge0 = line.split(' = ')[1].strip('"')
        if 'vars.network_jexge1 = ' in line:
            is_jexge1 = line.split(' = ')[1].strip('"')
        if 'vars.network_jexxe0 = ' in line:
            is_jexxe0 = line.split(' = ')[1].strip('"')
        if 'vars.network_jexxe1 = ' in line:
            is_jexxe1 = line.split(' = ')[1].strip('"')
        if 'vars.network_hp1810v2 = ' in line:
            is_hp1810v2 = line.split(' = ')[1].strip('"')
        if 'vars.network_des1210 = ' in line:
            is_des1210 = line.split(' = ')[1].strip('"')
        if 'vars.network_dgs3100 = ' in line:
            is_dgs3100 = line.split(' = ')[1].strip('"')
        if 'vars.network_dgs3100s1 = ' in line:
            is_dgs3100s1 = line.split(' = ')[1].strip('"')
        if 'vars.network_dgs3100s2 = ' in line:
            is_dgs3100s2 = line.split(' = ')[1].strip('"')
        if 'vars.network_dgs3100s3 = ' in line:
            is_dgs3100s3 = line.split(' = ')[1].strip('"')
        if 'vars.network_switch = ' in line:
            is_switch = line.split(' = ')[1].strip('"')
        if 'vars.network_ports = ' in line:
            ifcount = line.split(' = ')[1]
    if (is_comware == "true" or is_s1700 == "true" or is_hp1810v2 == "true") and is_switch != "true":
        is_switch = "true"
        hostvars += 'vars.network_switch = "' + is_switch + '"' +'\n  '
    if is_switch == "true" and int(ifcount) > 7:
        if is_comware == "true":
            host_entry += '  import "hpv1910-int-{0}-ports-template"\n'.format(ifcount)
        elif is_esxg == "true":
            host_entry += '  import "esxg-int-{0}-ports-template"\n'.format(ifcount)
        elif is_s1700 == "true":
            host_entry += '  import "s1700-int-{0}-ports-template"\n'.format(ifcount)
        elif is_sg300 == "true":
            host_entry += '  import "sg300-int-{0}-ports-template"\n'.format(ifcount)
        elif is_jexxe0 == "true":
            host_entry += '  import "jexxe0-int-{0}-ports-template"\n'.format(ifcount)
        elif is_jexxe1 == "true":
            host_entry += '  import "jexxe1-int-{0}-ports-template"\n'.format(ifcount)
        elif is_jexge0 == "true":
            host_entry += '  import "jexge0-int-{0}-ports-template"\n'.format(ifcount)
        elif is_jexge1 == "true":
            host_entry += '  import "jexge1-int-{0}-ports-template"\n'.format(ifcount)
        elif is_hp1810v2 == "true":
            host_entry += '  import "hp1810v2-int-{0}-ports-template"\n'.format(ifcount)
        elif is_des1210 == "true":
            host_entry += '  import "des1210-int-{0}-ports-template"\n'.format(ifcount)
        elif is_dgs3100s1 == "true":
            host_entry += '  import "dgs3100s1-int-{0}-ports-template"\n'.format(ifcount)
        elif is_dgs3100s2 == "true":
            host_entry += '  import "dgs3100s2-int-{0}-ports-template"\n'.format(ifcount)
        elif is_dgs3100s3 == "true":
            host_entry += '  import "dgs3100s3-int-{0}-ports-template"\n'.format(ifcount)
        else:
            host_entry += '  import "int-{0}-ports-template"\n'.format(ifcount)

    host_entry += '  address = "{0}"\n'.format(ip)

    icon_image = ""
    '''Get icon based on vendor matches'''
    if vendor:
      try:
        icon_vendors_items = icon_vendors.iteritems()
      except AttributeError:
        icon_vendors_items = icon_vendors.items()
      for match, var in icon_vendors_items:
        if match in vendor:
            for icon_template in icon_filenames:
                icon_filename = icon_template % (var)
                if os.path.exists(icingaweb2_public+'/'+icon_filename):
                    icon_image = icon_filename
                    break
            if icon_image != "":
                break
    '''Get icon based on sysDescr matches'''
    try:
        icon_descriptors_items = icon_descriptors.iteritems()
    except AttributeError:
        icon_descriptors_items = icon_descriptors.items()
    for match, var in icon_descriptors_items:
        if match in sysdesc:
            for icon_template in icon_filenames:
                icon_filename = icon_template % (var)
                if os.path.exists(icingaweb2_public+'/'+icon_filename):
                    icon_image = icon_filename
                    break
            if icon_image != "":
                break

    action_urls = hdata['action_urls']

    if icon_image != "":
        host_entry += '  icon_image = "{0}"\n'.format(icon_image)
    if action_urls != "":
        host_entry += '  action_url = "{0}"\n'.format(action_urls)
    if location:
        host_entry += '  vars.location = "{0}"\n'.format(location)
    if vendor:
        host_entry += '  vars.vendor = "{0}"\n'.format(vendor)

    sysssh = 0
    ret, output, err = exec_command('nmap -p22 {0}'.format(ip))
    if ret and err:
        sysssh = 0
    else:
        sysssh = parse_nmap_port_scan(output, '22/tcp ')

    if sysssh == 1:
         hostvars += 'vars.ssh_port = ' + '22' +'\n  '

    systelnet = 0
    ret, output, err = exec_command('nmap -p23 {0}'.format(ip))
    if ret and err:
        systelnet = 0
    else:
        systelnet = parse_nmap_port_scan(output, '23/tcp ')

    if systelnet == 1:
         hostvars += 'vars.telnet_port = ' + '23' +'\n  '

    if hostvars:
        host_entry += '  {0}\n'.format(hostvars)

    syshttp = hdata['syshttp']
    syshttps = hdata['syshttps']

    pardisk = ''
    sysdisk = ''
    if sysep != '':
        if sysos == 'Windows':
            pardisk = 'disk_win_path'
            sysdisk = 'C:'
        else:
            pardisk = 'disk_partitions'
            sysdisk = '/'

    if sysdisk != '':
        host_entry += '  vars.disks["disk"] = {\n'
        host_entry += '    /* No parameters. */\n'
        host_entry += '  }\n'
        host_entry += '  vars.disks["disk '+sysdisk+'"] = {\n'
        host_entry += '    '+pardisk+' = "'+sysdisk+'"\n'
        host_entry += '  }\n'

    if syshttp == 1:
        host_entry += '  vars.http_vhosts["http"] = {\n'
        host_entry += '    http_vhost = "$check_address$"\n'
        host_entry += '    http_uri = "/"\n'
        host_entry += '  }\n'

    if syshttps == 1:
        host_entry += '  vars.http_vhosts["https"] = {\n'
        host_entry += '    http_vhost = "$check_address$"\n'
        host_entry += '    http_port = 443\n'
        host_entry += '    http_ssl = true\n'
        host_entry += '    http_uri = "/"\n'
        host_entry += '  }\n'

    host_entry += '}\n'

    return host_entry

def parse_nmap_port_scan(data, match):
    data_list = data.split('\n')
    ret = 0
    for line in data_list:
        if match in line and line is not None:
            line = line[len(match):].split(' ')[0]
            if line == 'open':
                ret = 1

    return ret

def parse_nmap_ssl_scan(data):
    data_list = data.split('\n')
    ret = 0
    got_tls1_2 = 0
    got_tls1_1 = 0
    got_tls1_0 = 0
    got_aes = 0
    got_3des = 0
    got_rc4 = 0
    for line in data_list:
        if "TLSv1.2:" in line and line is not None:
            got_tls1_2 = 1
        elif "TLSv1.1:" in line and line is not None:
            got_tls1_1 = 1
        elif "TLSv1.0:" in line and line is not None:
            got_tls1_0 = 1
        elif "_WITH_AES_" in line and line is not None:
            got_aes = 1
        elif "_WITH_3DES_" in line and line is not None:
            got_3des = 1
        elif "_WITH_RC4_" in line and line is not None:
            got_rc4 = 1
    if got_aes and got_tls1_2:
        ret = 1
    elif (got_3des or got_rc4) and (got_tls1_1 or got_tls1_0):
        ret = -1
    return ret

def compile_hvars(sysdesc, devdesc):
    sys_descriptors = {
        'RouterOS': 'vars.network_mikrotik = "true"',
        'Baseline Switch': 'vars.network_switch = "true"',
        'Comware Platform': 'vars.network_switch = "true"',
        'HP 1810': 'vars.network_switch = "true"',
        'OfficeConnect': 'vars.network_switch = "true"',
        'ProCurve': 'vars.network_switch = "true"',
        'PROCURVE': 'vars.network_switch = "true"',
        'PoEP Switch': 'vars.network_switch = "true"',
        'SuperStack': 'vars.network_switch = "true"',
        'DES-1210': 'vars.network_switch = "true"',
        'DGS-1210': 'vars.network_switch = "true"',
        'Managed Switch': 'vars.network_switch = "true"',
        'SmartPro Switch': 'vars.network_switch = "true"',
        'SMC8024L': 'vars.network_switch = "true"',
        'Ethernet Switch': 'vars.network_switch = "true"',
        'Gigabit Switch': 'vars.network_switch = "true"',
        'WebSmart Switch': 'vars.network_switch = "true"',
        'EdgeSwitch': 'vars.network_switch = "true"',
        'Canon iR': 'vars.network_printer = "true"',
        'Develop ineo': 'vars.network_printer = "true"',
        'JETDIRECT': 'vars.network_printer = "true"',
        'Lexmark CS': 'vars.network_printer = "true"',
        'Lexmark MS': 'vars.network_printer = "true"',
        'Lexmark MX': 'vars.network_printer = "true"',
        'Lexmark XM': 'vars.network_printer = "true"',
        'Lexmark E3': 'vars.network_printer = "true"',
        'Lexmark T6': 'vars.network_printer = "true"',
        'Network Printer': 'vars.network_printer = "true"',
        'Printing System': 'vars.network_printer = "true"',
        'Xerox WorkCentre': 'vars.network_printer = "true"',
        'FreeBSD':'vars.os = "FreeBSD"',
        'Linux':'vars.os = "Linux"',
        'Windows':'vars.os = "Windows"',
        'pfSense': 'vars.os_distributor = "pfSense"',
        'XIGMANAS': 'vars.os_distributor = "XigmaNAS"',
        'Debian': 'vars.os_distributor = "Debian"',
        'Ubuntu': 'vars.os_distributor = "Ubuntu"',
        ' PVE ': 'vars.os_distributor = "Proxmox"',
        'XCP-ng': 'vars.os_distributor = "XCP-ng"',
        'XenServer':  'vars.os_distributor = "XenServer"',
        'Debian ': 'vars.agent_services = true',
        'Ubuntu ': 'vars.agent_services = true',
        'Windows ': 'vars.agent_services = true',
        'APC Web/SNMP': 'vars.ups_apc = "true"',
    }
    dev_descriptors = {
        'Brother HL': 'vars.network_printer = "true"',
        'Brother MFC': 'vars.network_printer = "true"',
        'bizhub': 'vars.network_printer = "true"',
        'Canon LBP': 'vars.network_printer = "true"',
        'Laserjet': 'vars.network_printer = "true"',
        'LaserJet': 'vars.network_printer = "true"',
        'Officejet': 'vars.network_printer = "true"',
        'OfficeJet': 'vars.network_printer = "true"',
        'Samsung CL': 'vars.network_printer = "true"',
        'Samsung ML': 'vars.network_printer = "true"',
        'SHARP MX': 'vars.network_printer = "true"',
    }

    hostvars = ''
    if sysdesc != '':
        hostvars += 'vars.description = "' + sysdesc + '"'+'\n  '
    if devdesc != '':
        hostvars += 'vars.device_description = "' + devdesc + '"'+'\n  '

    '''Append hostvars based on sysDescr matches'''
    try:
        sys_descriptors_items = sys_descriptors.iteritems()
    except AttributeError:
        sys_descriptors_items = sys_descriptors.items()
    for match, var in sys_descriptors_items:
        if match in sysdesc:
            hostvars += var +'\n  '
    '''Append hostvars based on devDescr matches'''
    try:
        dev_descriptors_items = dev_descriptors.iteritems()
    except AttributeError:
        dev_descriptors_items = dev_descriptors.items()
    for match, var in dev_descriptors_items:
        if match in devdesc:
            hostvars += var +'\n  '

    return hostvars

def handle_netscan(cidr):
    '''
    Scan network with nmap using ping only
    '''
    start = time.time()

    print("Starting scan for "+cidr)

    ret, output, err = exec_command('nmap -sn -sP -T3 {0}'.format(cidr))
    if ret and err:
        sys.stderr.write('There was a problem performing the scan - is the network reachable?')
        sys.exit(1)
    else:
        print("Scan took %s seconds" % (time.time() - start))
        data = parse_nmap_scan(output)
        if data:
            return data
        else:
           sys.stderr.write('Unable to parse nmap scan results! Please report this issue')
           sys.exit(1)

def parse_nmap_scan(data):
    match = 'Nmap scan report for '
    mac_match = 'MAC Address: '
    data_list = data.split('\n')
    prev_line = ''
    hosts = []
    for line in data_list:
        if match in line and line is not None:
            if prev_line != '':
                hosts.append(prev_line)
                prev_line = ''

            line = line[len(match):].strip(' ')

            if '(' in line:
                remove = '()'
                for c in remove:
                    line = line.replace(c, '')

                line = ','.join(line.split(' '))

            prev_line = line
            #hosts.append(line)
        if mac_match in line and line is not None:
            maca = line[len(mac_match):].split(' ')[0]
            if prev_line != '':
                hosts.append(prev_line+';'+maca)
                prev_line = ''

    if prev_line != '':
        hosts.append(prev_line)
        prev_line = ''

    return hosts

def snmpget_by_cl(host, credential, oid, timeout=1, retries=0):
    '''
    Slightly modified snmpget method from net-snmp source to loop through multiple communities if necessary
    '''

    data = {}
    versions = credential['version']
    communities = credential['community']
    ver_count = len(versions)
    com_count = len(communities)

    for h in range(0, ver_count):
      version = versions[h].strip()
      com_ok = 0
      for i in range(0, com_count):
        cmd = ''
        community = communities[i].strip()
        cmd = "snmpget -Oqv -v %s -c %s -r %s -t %s %s %s" % (
            version, community, retries, timeout, host, oid)

        returncode, output, err = exec_command(cmd)

        #print(returncode, output, err)
        if returncode and err:
            if i < com_count:
                continue
            else:
                data['error'] = str(err)
        else:
            try:
                data['output'] = output
                data['community'] = community
                data['version'] = version
                com_ok = 1
                #Got the data, now get out
                break
            except Exception as e:
                print("There was a problem appending data to the dict {0}".format(e))
      if com_ok == 1:
        break

    return data

def snmpwalk_by_cl(host, version, community, oid, timeout=1, retries=0):
    '''
    Slightly modified snmpwalk method from net-snmp
    '''

    data = {}

    cmd = "snmpwalk -v %s -Cc -c %s %s %s" % (
            version, community, host, oid)

    returncode, output, err = exec_command(cmd)

    #print(returncode, output, err)
    if returncode and err:
        data['error'] = str(err)
    else:
        try:
            data['output'] = output
            data['community'] = community
        except Exception as e:
            print("There was a problem appending data to the dict {0}".format(e))

    return data

def snmpwalk_tree_valid(host, version, community, oid, timeout=1, retries=0):
        ret = 0
        if community == '' or community == 'unknown':
            return ret

        match = oid[2:] + '.'
        data = snmpwalk_by_cl(host, version, community, oid, timeout, retries)

        try:
            output = data['output'].split('\n')
            for line in output:
                if match in line:
                    ret = 1
                    break
        except:
            output = ''

        return ret

def snmpwalk_get_tree(host, version, community, oid, timeout=1, retries=0):
        is_valid = 0
        output = list()
        if community == '' or community == 'unknown':
            return output

        match = oid[2:] + '.'
        data = snmpwalk_by_cl(host, version, community, oid, timeout, retries)

        try:
            output = data['output'].split('\n')
            for line in output:
                if match in line:
                    is_valid = 1
                    break
        except:
            output = list()

        if not is_valid:
            output = list()

        return output

def snmpwalk_get_value(host, version, community, oid, default='', timeout=1, retries=0):
        ret = default
        output = list()
        if community == '' or community == 'unknown':
            return ret

        match = oid[2:]
        data = snmpwalk_by_cl(host, version, community, oid, timeout, retries)

        try:
            output = data['output'].split('\n')
            for line in output:
                if match in line:
                    line = line.split('.')[-1]
                    ret = ': '.join(line.split(': ')[1:]).strip('"')
                    break
        except:
            output = list()

        return ret

def exec_command(command):
    """Execute command.
       Return a tuple: returncode, output and error message(None if no error).
    """
    sub_p = subprocess.Popen(command,
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    output, err_msg = sub_p.communicate()
    if output:
        output = output.decode(encoding='utf-8',errors='backslashreplace')
    return (sub_p.returncode, output, err_msg)


if __name__ == "__main__":
    main()
    sys.exit(0)
