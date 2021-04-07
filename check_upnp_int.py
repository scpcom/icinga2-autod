#!/usr/bin/env python3
import sys
import requests
import xml.etree.ElementTree as ElementTree
import time
import csv

ip = '192.168.0.1'
tr64_port = 49000
tr64_wancmnifc_control_url = "/igdupnp/control/WANCommonIFC1"
o_delta = 300      # delta of time of perfcheck (default 5min)

getSchema = "schemas-upnp-org"
getService = "WANCommonInterfaceConfig"
getAction = "GetCommonLinkProperties"
getProperty = "NewPhysicalLinkStatus"

if len(sys.argv) > 1:
   args = sys.argv[1:]
   argn = ''
   for arg in args:
       if len(arg) == 2 and arg[0] == '-': 
           argn = arg
       elif argn == '-H':
           ip = arg
       elif argn == '-p':
           tr64_port = int(arg)
       elif argn == '-C':
           tr64_wancmnifc_control_url = arg
       elif argn == '-d':
           o_delta = int(arg)

url='http://'+ip+':'+str(tr64_port)+tr64_wancmnifc_control_url

o_base_dir    = "/tmp/tmp_Icinga_int."
o_checkperf   = True
o_highperf    = False
timenow       = time.time()
trigger       = timenow - (o_delta - (o_delta / 10))
trigger_low   = timenow - 3 * o_delta

# check if the counter is back to 0 after 2^32 / 2^64.
# First set the modulus depending on highperf counters or not
if o_highperf:
    overfl_mod = 18446744073709551616
else:
    overfl_mod = 4294967296

int_status = 0
o_host = ip
o_port = tr64_port
descr = "wan"
perf_inoct = 0
perf_outoct = 0

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

# based on code from check_snmp_int.pl
def calc_bandwith_checks():
    usable_data  = 1
    # Make the bandwith checks if necessary
    if (o_checkperf and int_status == 1):
        temp_file_name = descr
        temp_file_name = o_base_dir + o_host + "." + str(o_port) + "." + temp_file_name

        # First, read entire file
        r_code, n_rows, file_values = read_check_file(temp_file_name)
        #print("File read returns : "+str(r_code)+" with "+str(n_rows)+" rows")

        checkperf_out_raw = [ None, None ]
        # make the checks if the file is OK
        if (r_code == 0):
            j = n_rows - 1
            for file_value in file_values:
                file_value_time = float(file_value[0])
                file_value_inoct = int(file_value[1])
                file_value_outoct = int(file_value[2])
                if (file_value_time < trigger):
                    if (file_value_time > trigger_low):
                        # Check counter (s)
                        if perf_inoct >= file_value_inoct:
                            overfl = 0
                        else:
                            overfl = overfl_mod
                        checkperf_out_raw[0] = ((overfl + perf_inoct - file_value_inoct)
                            / (timenow - file_value_time))

                        if perf_outoct >= file_value_outoct:
                            overfl = 0
                        else:
                            overfl = overfl_mod
                        checkperf_out_raw[1] = ((overfl + perf_outoct - file_value_outoct)
                            / (timenow - file_value_time))
                if checkperf_out_raw[0]:
                    break

        # Put the new values in the array and write the file
        new_values = str(timenow) +';'+ str(perf_inoct) +';'+ str(perf_outoct)
        n_rows += 1
        r_code = write_check_file(temp_file_name, new_values.split(';'))
        #print("Write file returned : "+str(r_code))

        # print the other checks if it was calculated
        if not checkperf_out_raw[0]:
            #print(" No usable data on file (" + str(n_rows) + " rows) ")
            usable_data  = 0
        return usable_data, checkperf_out_raw

def upnp_get_action(actionName):
    global ReturnXml
    global ns
    getUrn = "urn:"+getSchema+":"+"service"+":"+getService+":"+"1"

    #print(url)
    #print(getUrn)

    ns= {
        "u": getUrn
    }

    headers = {'content-type': 'text/xml', 'SOAPAction': '"{0}#{1}"'.format(getUrn, actionName)}
    body = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
  <u:{0} xmlns:u="{1}" />
</s:Body>
</s:Envelope>""".format(actionName, getUrn)

    try:
        response = requests.post(url,data=body,headers=headers)
    except:
        response = None
    if response is not None:
        content = response.content.decode('utf8')
        ReturnXml = ElementTree.fromstring(content)
    else:
        ReturnXml = None
    return ReturnXml

def upnp_get_prop(propName):
    propValue = ''
    if ReturnXml is not None:
        propreties = ReturnXml.findall(".//"+propName, ns)
        for p in propreties:
           propValue = p.text
           break

    #print(propName+': '+propValue)
    return propValue

upnp_get_action(getAction)
status = upnp_get_prop(getProperty)
if status == 'Up':
    status = 'UP'
    int_status = 1
else:
    status = 'DOWN'
#print('Status: '+status)
dMaxBitRate = upnp_get_prop('NewLayer1DownstreamMaxBitRate')
if dMaxBitRate == '':
    dMaxBitRate = 0
else:
    dMaxBitRate = int(dMaxBitRate)
uMaxBitRate = upnp_get_prop('NewLayer1UpstreamMaxBitRate')
if uMaxBitRate == '':
    uMaxBitRate = 0
else:
    uMaxBitRate = int(uMaxBitRate)
#print('Max: '+dMaxBitRate+'/'+uMaxBitRate+' bps')
upnp_get_action('GetAddonInfos')
dTotalBytesReceived = upnp_get_prop('NewTotalBytesReceived')
uTotalBytesSent = upnp_get_prop('NewTotalBytesSent')
dReceiveRate = upnp_get_prop('NewByteReceiveRate')
uSendRate = upnp_get_prop('NewByteSendRate')
dMbps = ''
uMbps = ''
if dReceiveRate == '' and uSendRate == '':
    perf_inoct = int(dTotalBytesReceived)
    perf_outoct = int(uTotalBytesSent)
    usable, rates = calc_bandwith_checks()
    if usable:
        dReceiveRate = str(int(rates[0]))
        uSendRate = str(int(rates[1]))
if dReceiveRate != '' and uSendRate != '':
    dReceiveRate = int(dReceiveRate) * 8
    uSendRate = int(uSendRate) * 8
    #print('Current: '+str(dReceiveRate)+'/'+str(uSendRate)+' bps')
    dMbps = float(dReceiveRate)/1000000
    uMbps = float(uSendRate)/1000000
    dMbps = "{:.1f}".format(dMbps)
    uMbps = "{:.1f}".format(uMbps)
dWarn = int(dMaxBitRate/10*9)
dCrit = dMaxBitRate
uWarn = int(uMaxBitRate/10*9)
uCrit = uMaxBitRate
if status == 'UP':
    print("wan:{12} ({0}Mbps/{1}Mbps):1 UP: OK | 'wan_in_bps'={2};{3};{4};{5};{6} 'wan_out_bps'={7};{8};{9};{10};{11}".format(dMbps, uMbps, dReceiveRate, dWarn, dCrit, 0, dMaxBitRate, uSendRate, uWarn, uCrit, 0, uMaxBitRate, status))
else:
    print("wan:DOWN: 1 int NOK : CRITICAL")
