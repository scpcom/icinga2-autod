#!/usr/bin/env python3
import sys
import requests
import xml.etree.ElementTree as ElementTree

"""
Parameters:
  -H host
  -p port
  -C service control url
  -U schema
  -S service name
  -A action name
  -P property name or * for all
Examples:
./check_upnp.py -H 192.168.178.1 -P '*'
./check_upnp.py -H 192.168.178.1 -A GetAddonInfos -P '*'
./check_upnp.py -H 192.168.178.1 -U schemas-any-com -C /upnp/control/fritzbox -S fritzbox -A GetMaclist -P '*'
"""

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
       elif argn == '-U':
           getSchema = arg
       elif argn == '-S':
           getService = arg
       elif argn == '-A':
           getAction = arg
       elif argn == '-P':
           getProperty = arg

if getProperty == '*':
    getProperty = ''

url='http://'+ip+':'+str(tr64_port)+tr64_wancmnifc_control_url
getUrn = "urn:"+getSchema+":"+"service"+":"+getService+":"+"1"

#print(url)
#print(getUrn)

ns= {
    "u": getUrn
}

headers = {'content-type': 'text/xml', 'SOAPAction': '"{0}#{1}"'.format(getUrn, getAction)}
body = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
  <u:{0} xmlns:u="{1}" />
</s:Body>
</s:Envelope>""".format(getAction, getUrn)

bodyTag = '{'+'http://schemas.xmlsoap.org/soap/envelope/'+'}'+'Body'
responseTag = '{'+getUrn+'}'+getAction+'Response'

monitorValue = ''
content = None
ReturnXml = None
try:
    response = requests.post(url,data=body,headers=headers)
except:
    response = None

if response is not None:
    try:
        content = response.content.decode('utf8')
    except:
        content = None

if content is not None:
    try:
        ReturnXml = ElementTree.fromstring(content)
    except:
        ReturnXml = None
        print(content)

if ReturnXml is not None:
    propreties = ReturnXml.findall(".//"+getProperty, ns)
    for p in propreties:
       monitorValue = p.text
       if p.tag == bodyTag or p.tag == responseTag:
           continue
       elif getProperty == '':
           print(p.tag+': '+p.text)
       else:
           break

if getProperty != '':
    print(getProperty+': '+monitorValue)
