#!/usr/bin/env python3
import sys
import requests
import xml.etree.ElementTree as ElementTree

ip = '192.168.0.1'
tr64_port = 49000
tr64_wancmnifc_control_url = "/igdupnp/control/WANCommonIFC1"

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

url='http://'+ip+':'+str(tr64_port)+tr64_wancmnifc_control_url

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
else:
    status = 'DOWN'
#print('Status: '+status)
dMaxBitRate = upnp_get_prop('NewLayer1DownstreamMaxBitRate')
uMaxBitRate = upnp_get_prop('NewLayer1UpstreamMaxBitRate')
#print('Max: '+dMaxBitRate+'/'+uMaxBitRate+' bps')
upnp_get_action('GetAddonInfos')
dReceiveRate = upnp_get_prop('NewByteReceiveRate')
uSendRate = upnp_get_prop('NewByteSendRate')
dMbps = ''
uMbps = ''
if dReceiveRate != '' and uSendRate != '':
    dReceiveRate = int(dReceiveRate) * 8
    uSendRate = int(uSendRate) * 8
    #print('Current: '+str(dReceiveRate)+'/'+str(uSendRate)+' bps')
    dMbps = float(dReceiveRate)/1000000
    uMbps = float(uSendRate)/1000000
    dMbps = "{:.1f}".format(dMbps)
    uMbps = "{:.1f}".format(uMbps)
dWarn = ''
dCrit = ''
uWarn = ''
uCrit = ''
if status == 'UP':
    print("wan:{12} ({0}Mbps/{1}Mbps):1 UP: OK | 'wan_in_bps'={2};{3};{4};{5};{6} 'wan_out_bps'={7};{8};{9};{10};{11}".format(dMbps, uMbps, dReceiveRate, dWarn, dCrit, 0, dMaxBitRate, uSendRate, uWarn, uCrit, 0, uMaxBitRate, status))
else:
    print("wan:DOWN: 1 int NOK : CRITICAL")
