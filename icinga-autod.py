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
    credential['version'] = '2c'
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

        if ',' in host:
            hostname, host = host.split(',')

        data = snmpget_by_cl(host, credential, oids)

        '''TODO: clean up this logic...'''
        try:
            output = data['output'].split('\n')
            community = data['community']

	    hostname = output[0].strip('"')
            sysdesc = output[1].strip('"').strip('\r')
            syslocation = output[-3].strip('"')
            sysobject = output[-2].strip('"') 

        except:
            community = 'unknown'
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
	    'community': community, 'snmp_version': credential['version'], 'hostname': hostname, 'sysdesc': sysdesc, 'syslocation': syslocation, 'vendor' : vendor }

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

    f = open(filename, 'w')

    for ip, hdata in data.iteritems():
	have_snmp = 0
	if hdata['community'] != '' and  hdata['community'] != 'unknown':
	    have_snmp = 1

	devdesc = ''
	if have_snmp == 1:
	    data = snmpwalk_by_cl(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.25.3.2.1.3.1')
	else:
	    data = ''

	try:
            output = data['output'].split('\n')
            for line in output:
                if '.3.6.1.2.1.25.3.2.1.3.1' in line:
                    line = line.split('.')[-1]
                    devdesc = ': '.join(line.split(': ')[1:]).strip('"')
                    #print devdesc

	except:
            output = ''

	hostvars = compile_hvars(hdata['sysdesc'], devdesc)
	hostlocation = location
	if hdata['syslocation'] != '':
		hostlocation = hdata['syslocation']

	if not hdata['hostname']:
	    hostname = ip
	else:
	    hostname = hdata['hostname']

	ifcount = 0
	is_comware = "false"
	port_filter = ['CPU', 'TRK', 'NULL', 'Vlan']
	if have_snmp == 1:
	    data = snmpwalk_by_cl(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.2.2.1.2')
	else:
	    data = ''

	try:
            output = data['output'].split('\n')
            for line in output:
                if '.3.6.1.2.1.2.2.1.2.' in line:
                    line = line.split('.')[-1]
                    ifno = int(line.split(' ') [0])
                    ifna = ': '.join(line.split(': ')[1:]).strip('"')

                    ifskip = 0
                    for prefix in port_filter:
                        if ifna.startswith(prefix):
                            ifskip = 1

                    if ifskip == 0 and ifno > ifcount:
                        ifcount = ifno
                        #print str(ifno) + ': ' + ifna
                    if ifna.startswith('GigabitEthernet1/0/'):
                        is_comware = "true"

	except:
            output = ''

	chassisid = ''
	if have_snmp == 1:
	    data = snmpwalk_by_cl(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.17.1.1.0')
	else:
	    data = ''

	try:
            output = data['output'].split('\n')
            for line in output:
                if '.3.6.1.2.1.17.1.1.0' in line:
                    line = line.split('.')[-1]
                    chassisid = ': '.join(line.split(': ')[1:]).strip('"')
                    chassisid = ':'.join(chassisid.split(' ')[:-1])
                    #print chassisid

	except:
	    output = ''

	if have_snmp == 1:
	    data = snmpwalk_by_cl(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.2.2.1.6')
	else:
	    data = ''

	try:
            output = data['output'].split('\n')
            print str(ip) + ' ' + hdata['hostname'] + ' Port IDs'
            if chassisid != '':
                print chassisid + ' chassis'
            for line in output:
                if '.3.6.1.2.1.2.2.1.6.' in line:
                    line = line.split('.')[-1]
                    ifno = line.split(' = ') [0]
                    if int(ifno) < 10:
                        ifno = '0'+ifno
                    maca = ': '.join(line.split(': ')[1:]).strip('"')
                    maca = ':'.join(maca.split(' ')[:-1])
                    print maca + ' port ' + ifno

	except:
	    output = ''

	if have_snmp == 1:
	    data = snmpwalk_by_cl(ip, hdata['snmp_version'], hdata['community'], '.1.3.6.1.2.1.17.7.1.2.2.1.2')
	else:
	    data = ''

	try:
            output = data['output'].split('\n')
            print str(ip) + ' ' + hdata['hostname'] + ' MAC Table'
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
                    print maca + ' on port ' + ifno

	except:
	    output = ''

	#print str(ifcount) + ' interfaces'
	if is_comware == "true":
	    hostvars += 'vars.network_comware = "' + is_comware + '"' +'\n  '
	if ifcount > 0:
	    hostvars += 'vars.network_ports = ' + str(ifcount) +'\n  '
	if hdata['community'] != '' and  hdata['community'] != 'unknown':
	    hostvars += 'vars.snmp_community = "' + hdata['community'] + '"' +'\n  '
	    hostvars += 'vars.snmp_version = "' + hdata['snmp_version'] + '"' +'\n  '
	    if hdata['snmp_version'] == '2c':
	        hostvars += 'vars.snmp_v2 = "' 'true' + '"' +'\n  '
	host_entry = build_host_entry(hostname, str(ip), hostlocation, hdata['vendor'], str(hostvars))

	f.write(host_entry)

    f.close()

    return filename

def build_host_entry(hostname, ip, location, vendor, hostvars):
    host_entry = ( 'object Host "%s" {\n'
		   '  import "generic-host"\n'
		 ) % (hostname)

    linevars = hostvars.split('\n')
    is_comware = "false"
    is_switch = "false"
    ifcount = 0
    for line in linevars:
        if 'vars.network_comware = ' in line:
            is_comware = line.split(' = ')[1].strip('"')
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
        else:
            host_entry += '  import "int-{0}-ports-template"\n'.format(ifcount)

    host_entry += '  address = "{0}"\n'.format(ip)
    if location:
	host_entry += '  vars.location = "{0}"\n'.format(location)
    if vendor:
	host_entry += '  vars.vendor = "{0}"\n'.format(vendor)
    if hostvars: 
	host_entry += '  {0}\n'.format(hostvars)

    syshttp = 0
    ret, output, err = exec_command('nmap -p80 {0}'.format(ip))
    if ret and err:
        syshttp = 0
    else:
        syshttp = parse_nmap_port_scan(output)

    if syshttp == 1:
        host_entry += '  vars.http_vhosts["http"] = {\n'
        host_entry += '    http_uri = "/"\n'
        host_entry += '  }\n'

    host_entry += '}\n'

    return host_entry

def parse_nmap_port_scan(data):
    data_list = data.split('\n')
    match = '80/tcp '
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
	'OfficeConnect': 'vars.network_switch = "true"',
	'ProCurve': 'vars.network_switch = "true"',
	'Linux':'vars.os = "Linux"', 
	'Windows':'vars.os = "Windows"',
	'APC Web/SNMP': 'vars.ups_apc = "true"', 
    }
    dev_descriptors = {
        'Laserjet': 'vars.network_printer = "true"',
        'LaserJet': 'vars.network_printer = "true"',
        'Officejet': 'vars.network_printer = "true"',
        'OfficeJet': 'vars.network_printer = "true"',
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
    data_list = data.split('\n')
    match = 'Nmap scan report for '
    hosts = []
    for line in data_list:
        if match in line and line is not None:
            line = line[len(match):].strip(' ')

            if '(' in line:
                remove = '()'
                for c in remove:
                    line = line.replace(c, '')

                line = ','.join(line.split(' '))

            hosts.append(line)

    return hosts

def snmpget_by_cl(host, credential, oid, timeout=1, retries=0):
    '''
    Slightly modified snmpget method from net-snmp source to loop through multiple communities if necessary
    '''

    data = {}
    version = credential['version']
    communities = credential['community']
    com_count = len(communities)

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
		#Got the data, now get out
		break	
	    except Exception, e:
		print "There was a problem appending data to the dict " + str(e)

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
