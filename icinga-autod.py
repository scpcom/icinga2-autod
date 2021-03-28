#!/usr/bin/env python
import util.checkpkg as checkpkg

checkpkg.check(['nmap', 'snmp', 'net-snmp-utils'])

import sys
import subprocess
import json

try:
    import argparse
except ImportError:
    checkpkg.check(['python-argparse'])

import time
import socket
import util.ianaparse as ianaparse

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

    return parser

def main():

    global debug

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
    except Exception, e:
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

        data = snmpget_by_cl(host, credential, oids)

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
	
	v_match = vendor_match(numbers, sysobject)	

	if v_match:
	    vendor = v_match['o'].strip('"')
	else:
	    vendor = None
	    
	all_hosts[host] = { 
	    'community': community, 'snmp_version': snmp_version, 'hostname': hostname, 'hostmac': hostmac, 'sysdesc': sysdesc, 'syslocation': syslocation, 'vendor' : vendor }

	if debug:
	    print host, sysobject, all_hosts[host]

    print "\n"
    print("Discovery took %s seconds" % (time.time() - start_time))
    print "Writing data to config file. Please wait"

    outfile = compile_hosts(all_hosts, location)
    print "Wrote data to "+outfile

def vendor_match(numbers, sysobject):
    if sysobject:
	#Possible prefixes in sysObjectID OID largely dependent on MIB used
	prefixes = ['SNMPv2-SMI::enterprises.', 'iso.3.6.1.4.1.', '1.3.6.1.4.1.', 'NET-SNMP-MIB::netSnmpAgentOIDs.']
	
	for prefix in prefixes:
	    if sysobject.startswith(prefix):
	        sysobject = sysobject[len(prefix):]
	
	values = sysobject.split('.')
	#first value will be the enterprise number
	vendor_num = values[0]

	try:
	    vendor_string = numbers[vendor_num]
	    return vendor_string

	except Exception, e:
	    sys.stderr.write('Unknown sysObjectID prefix encountered - you can add it to the prefix list in vendor_match(), but please report this on GitHub\n'+str(e))
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
    for k,v in vars(args).iteritems():
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
	
    for flag, val in check_flags.iteritems():
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
	print "No hosts found! Is the network reachable? \nExiting..."
	sys.exit(0)
    else:
        return count

def compile_hosts(data, location):
    if location: 
	loc = location.lower()
        filename = 'hosts_'+loc+'.conf'
    else:
	filename = 'discovered_hosts.conf'

    macp_filename = filename.replace('.conf', '_mac_ports.csv')
    mact_filename = filename.replace('.conf', '_mac_table.csv')
    lldt_filename = filename.replace('.conf', '_mac_lldp.csv')

    f = open(filename, 'w')
    macp_f = open(macp_filename, 'w')
    mact_f = open(mact_filename, 'w')
    lldt_f = open(lldt_filename, 'w')

    for ip, hdata in data.iteritems():
	have_snmp = 0
	if hdata['community'] != '' and  hdata['community'] != 'unknown':
	    have_snmp = 1

	devdesc = snmpwalk_get_value(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.25.3.2.1.3.1', '')

	hostvars = compile_hvars(hdata['sysdesc'], devdesc)
	hostlocation = location
	if hdata['syslocation'] != '':
		hostlocation = hdata['syslocation']

	if not hdata['hostname']:
	    hostname = ip
	else:
	    hostname = hdata['hostname']

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
	is_hp1810v2 = "false"
	is_dgs3100 = "false"
	is_dgs3100s1 = "false"
	is_dgs3100s2 = "false"
	is_dgs3100s3 = "false"
	port_filter = ['IP Interface', 'CPU', 'TRK', 'NULL', 'InLoopBack', 'Vlan', 'Console Port', 'Management Port', 'VLAN', '802.1Q Encapsulation', 'Stack Aggregated', 'rif0', 'vlan', 'Internal Interface', 'DEFAULT_VLAN', 'loopback interface', 'stack-port']
	alias_filter = ['MAC Layer LightWeight Filter', 'QoS Packet Scheduler', 'WiFi Filter Driver', 'Kerneldebugger']
	type_filter = [1, 23, 24, 53, 131, 161]

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
                    #print str(ifno)+';'+str(ifty)+';'+ifna+';'+ifde+';'+ifal

                    ifskip = 0
                    for prefix in port_filter:
                        if ifna.startswith(prefix):
                            ifskip = 1
                    for filali in alias_filter:
                        if filali in ifal:
                            ifskip = 1
                    for filtyp in type_filter:
                        if ifty == filtyp:
                            ifskip = 1
                    if ifna.startswith('ch') and len(ifna) < 5:
                        ifskip = 1

                    if ifskip == 0 and ifno < iffirst:
                        iffirst = ifno
                    if ifskip == 0 and ifno > ifcount:
                        ifcount = ifno
                        ifentries = ifentries + 1
                        #print str(ifno)+';'+str(ifty)+';'+ifna+';'+ifde+';'+ifal
                    if ifna.startswith('GigabitEthernet1/0/'):
                        is_comware = "true"
                    if ifna.startswith('Port  '):
                        is_hp1810v2 = "true"
                    if ifna.startswith('1:'):
                        is_dgs3100 = "true"
                        is_dgs3100s1 = "true"
                    if ifna.startswith('2:'):
                        is_dgs3100 = "true"
                        is_dgs3100s2 = "true"
                    if ifna.startswith('3:'):
                        is_dgs3100 = "true"
                        is_dgs3100s3 = "true"

	chassisid = snmpwalk_get_value(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.17.1.1.0', '')
	if chassisid != '':
		chassisid = ':'.join(chassisid.split(' ')[:-1])

	if hdata['hostmac'] != '':
	    #print str(ip) + ' ' + hdata['hostname'] + ' got Host MAC'
	    macp_f.write(hdata['hostmac'] + ';' + 'arp' + ';' + str(ip) + ';' + hdata['hostname'] +'\n')

	portcount = 0

	if len(phys_output) > 0:
            print str(ip) + ' ' + hdata['hostname'] + ' got Port IDs'
            if chassisid != '':
                macp_f.write(chassisid + ';' + 'chassis' + ';' + str(ip) + ';' + hdata['hostname'] +'\n')
            for line in phys_output:
                if '.3.6.1.2.1.2.2.1.6.' in line:
                    line = line.split('.')[-1]
                    ifno = int(line.split(' = ')[0])
                    maca = ': '.join(line.split(': ')[1:]).strip('"')
                    maca = ':'.join(maca.split(' ')[:-1])

                    ifna = ''
                    for name in name_output:
                        if '.3.6.1.2.1.31.1.1.1.1.'+str(ifno) in name:
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

                    ifskip = 0
                    for prefix in port_filter:
                        if ifna.startswith(prefix):
                            ifskip = 1
                    for filali in alias_filter:
                        if filali in ifal:
                            ifskip = 1
                    for filtyp in type_filter:
                        if ifty == filtyp:
                            ifskip = 1

                    if maca and maca != '':
                        if ifentries < 8 and ifad == 1 and ifop == 1 and not ifskip:
                            if ifna == '':
                                ifna = ifde
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
                        macp_f.write(maca + ';' + ifno + ';' + str(ip) + ';' + hdata['hostname'] +'\n')

	have_mact = 0
	output = snmpwalk_get_tree(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.17.7.1.2.2.1.2')

	if len(output) > 0:
            print str(ip) + ' ' + hdata['hostname'] + ' got MAC Table'
            for line in output:
                if '.3.6.1.2.1.17.7.1.2.2.1.2.' in line:
                    ifno = ': '.join(line.split(': ')[1:]).strip('"')
                    line = line.split(' = ')[0]
                    line = line.split('.')[14:]
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
            print str(ip) + ' ' + hdata['hostname'] + ' got MAC Table'
            for line in output:
                if '.3.6.1.2.1.17.4.3.1.2.' in line:
                    ifno = ': '.join(line.split(': ')[1:]).strip('"')
                    line = line.split(' = ')[0]
                    line = line.split('.')[11:]
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
                print str(ip) + ' ' + hdata['hostname'] + ' got LLDP Table'
            for line in output:
                if '.0.8802.1.1.2.1.4.1.1.5.' in line:
                    ifno = line.split('.')[12:][0]
                    line = '.'.join(line.split('.')[13:])
                    ifnr = line.split(' = ')[0]
                    maca = ': '.join(line.split(': ')[1:]).strip('"').replace(' ', ':').replace('-', ':').upper()
                    if maca[-1:] == ':':
                        maca = maca[:-1]
                    if len(maca) == 12 and not ':' in maca:
                        maca = maca[:2] + ':' + maca[2:4] + ':' + maca[4:6] + ':' + maca[6:8] + ':' + maca[8:10] + ':' + maca[10:12]
                    #print ifno+';'+ifnr+';'+maca
                    have_lldt = 1
                    lldt_f.write(maca + ';' + ifno + ';' + ifnr+';' + str(ip) + ';' + hdata['hostname'] +'\n')

	snmp_load_type = ""
	if snmpwalk_tree_valid(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.25.3.3.1.2'):
		snmp_load_type = "stand"
	if snmpwalk_tree_valid(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.4.1.2021.10.1.2'):
		snmp_load_type = "netsl"

	snmp_is_netsnmp = "false"
	if snmpwalk_tree_valid(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.4.1.2021.4.6.0'):
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
	if len(desc_output) > 0:
            for line in desc_output:
                if '.3.6.1.2.1.25.2.3.1.3.' in line:
                    line = '.'.join(line.split('.')[11:])
                    stno = int(line.split(' ') [0])
                    stna = ': '.join(line.split(': ')[1:]).strip('"')

                    stty = 0
                    for type in type_output:
                        if '.3.6.1.2.1.25.2.3.1.2.'+str(stno)+' ' in type:
                            type = '.'.join(type.split('.')[11:])
                            if '.3.6.1.2.1.25.2.1.' in type:
                                type = ': '.join(type.split(': ')[1:]).strip('"')
                                stty=int(type.split('.')[-1:][0])
                    if ':\\\\ Label:' in stna:
                        stna = stna.split(' Label:')[0]
                        stna = '\\\\'.join(stna.split('\\'))
                    #print str(stno)+';'+str(stty)+';'+stna
                    if stty == 2:
                        snmp_storage_mem_name=stna
                    elif stty == 3:
                        snmp_storage_swap_name=stna
                    elif stty == 4 and snmp_storage_disk_name == '':
                        snmp_storage_disk_name=stna

	#print str(ifcount) + ' interfaces'
	if is_comware == "true":
	    hostvars += 'vars.network_comware = "' + is_comware + '"' +'\n  '
	if is_hp1810v2 == "true":
	    hostvars += 'vars.network_hp1810v2 = "' + is_hp1810v2 + '"' +'\n  '
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
	if hdata['community'] != '' and  hdata['community'] != 'unknown':
	    hostvars += 'vars.snmp_community = "' + hdata['community'] + '"' +'\n  '
	    hostvars += 'vars.snmp_version = "' + hdata['snmp_version'] + '"' +'\n  '
	    if hdata['snmp_version'] == '2c':
	        hostvars += 'vars.snmp_v2 = "' 'true' + '"' +'\n  '

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
        if snmp_storage_mem_name != '':
             hostvars += 'vars.snmp_storage_mem_name = "' + snmp_storage_mem_name + '"' +'\n  '
        if snmp_storage_swap_name != '':
             hostvars += 'vars.snmp_storage_swap_name = "' + snmp_storage_swap_name + '"' +'\n  '
        if snmp_storage_disk_name != '':
             hostvars += 'vars.snmp_storage_disk_name = "' + snmp_storage_disk_name + '"' +'\n  '
        if hdata['hostmac'] != '':
            hostvars += 'vars.mac_address = "' + hdata['hostmac'] + '"' +'\n  '
	host_entry = build_host_entry(hostname, str(ip), hostlocation, hdata['vendor'], str(hostvars))

	f.write(host_entry)

    f.close()
    macp_f.close()
    mact_f.close()
    lldt_f.close()

    return filename

def build_host_entry(hostname, ip, location, vendor, hostvars):
    host_entry = ( 'object Host "%s" {\n'
		   '  import "generic-host"\n'
		 ) % (hostname)

    linevars = hostvars.split('\n')
    is_comware = "false"
    is_hp1810v2 = "false"
    is_dgs3100 = "false"
    is_dgs3100s1 = "false"
    is_dgs3100s2 = "false"
    is_dgs3100s3 = "false"
    is_switch = "false"
    ifcount = 0
    for line in linevars:
        if 'vars.network_comware = ' in line:
            is_comware = line.split(' = ')[1].strip('"')
        if 'vars.network_hp1810v2 = ' in line:
            is_hp1810v2 = line.split(' = ')[1].strip('"')
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
    if is_comware == "true" and is_switch != "true":
        is_switch = "true"
        hostvars += 'vars.network_switch = "' + is_switch + '"' +'\n  '
    if is_switch == "true" and ifcount > 7:
        if is_comware == "true":
            host_entry += '  import "hpv1910-int-{0}-ports-template"\n'.format(ifcount)
        elif is_hp1810v2 == "true":
            host_entry += '  import "hp1810v2-int-{0}-ports-template"\n'.format(ifcount)
        elif is_dgs3100s1 == "true":
            host_entry += '  import "dgs3100s1-int-{0}-ports-template"\n'.format(ifcount)
        elif is_dgs3100s2 == "true":
            host_entry += '  import "dgs3100s2-int-{0}-ports-template"\n'.format(ifcount)
        elif is_dgs3100s3 == "true":
            host_entry += '  import "dgs3100s3-int-{0}-ports-template"\n'.format(ifcount)
        else:
            host_entry += '  import "int-{0}-ports-template"\n'.format(ifcount)

    host_entry += '  address = "{0}"\n'.format(ip)
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

    syshttp = 0
    ret, output, err = exec_command('nmap -p80 {0}'.format(ip))
    if ret and err:
        syshttp = 0
    else:
        syshttp = parse_nmap_port_scan(output, '80/tcp ')

    if syshttp == 1:
        host_entry += '  vars.http_vhosts["http"] = {\n'
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
	'DGS-1210': 'vars.network_switch = "true"',
	'Managed Switch': 'vars.network_switch = "true"',
	'SMC8024L': 'vars.network_switch = "true"',
	'Canon iR': 'vars.network_printer = "true"',
	'Lexmark CS': 'vars.network_printer = "true"',
	'Lexmark MS': 'vars.network_printer = "true"',
	'Lexmark MX': 'vars.network_printer = "true"',
	'Lexmark XM': 'vars.network_printer = "true"',
	'Printing System': 'vars.network_printer = "true"',
	'Linux':'vars.os = "Linux"', 
	'Windows':'vars.os = "Windows"',
	'APC Web/SNMP': 'vars.ups_apc = "true"', 
    }
    dev_descriptors = {
        'Laserjet': 'vars.network_printer = "true"',
        'LaserJet': 'vars.network_printer = "true"',
        'Officejet': 'vars.network_printer = "true"',
        'OfficeJet': 'vars.network_printer = "true"',
        'SHARP MX': 'vars.network_printer = "true"',
    }

    hostvars = ''
    if sysdesc != '':
        hostvars += 'vars.description = "' + sysdesc + '"'+'\n  '
    if devdesc != '':
        hostvars += 'vars.device_description = "' + devdesc + '"'+'\n  '

    '''Append hostvars based on sysDescr matches'''
    for match, var in sys_descriptors.iteritems():
	if match in sysdesc:
	    hostvars += var +'\n  '
    '''Append hostvars based on devDescr matches'''
    for match, var in dev_descriptors.iteritems():
        if match in devdesc:
            hostvars += var +'\n  '

    return hostvars

def handle_netscan(cidr):
    '''
    Scan network with nmap using ping only
    '''
    start = time.time()

    print "Starting scan for "+cidr

    ret, output, err = exec_command('nmap -sn -sP -T3 {0}'.format(cidr))
    if ret and err:
        sys.stderr.write('There was a problem performing the scan - is the network reachable?')
	sys.exit(1)
    else:
	print ("Scan took %s seconds" % (time.time() - start))
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
	
	#print returncode, output, err
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
	    except Exception, e:
		print "There was a problem appending data to the dict " + str(e)
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

    #print returncode, output, err
    if returncode and err:
        data['error'] = str(err)
    else:
        try:
            data['output'] = output
            data['community'] = community
        except Exception, e:
            print "There was a problem appending data to the dict " + str(e)

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
	if community == '' and  community == 'unknown':
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
	if community == '' and  community == 'unknown':
	    return output

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
    return (sub_p.returncode, output, err_msg)


if __name__ == "__main__":
    main()
    sys.exit(0)
