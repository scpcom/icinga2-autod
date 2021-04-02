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
   ip = sys.argv[1]
if len(sys.argv) > 2:
   tr64_port = int(sys.argv[2])
if len(sys.argv) > 3:
   tr64_wancmnifc_control_url = sys.argv[3]

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

monitorValue = ''
try:
    response = requests.post(url,data=body,headers=headers)
except:
    response = None
if response is not None:
    content = response.content.decode('utf8')
    ReturnXml = ElementTree.fromstring(content)
    propreties = ReturnXml.findall(".//"+getProperty, ns)
    for p in propreties:
       monitorValue = p.text
       break

print(getProperty+': '+monitorValue)
