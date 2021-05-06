#!/usr/bin/env python3
import sys
from util.upnptools import upnp_process_description, upnp_print_schema, upnp_get_service, set_upnp_actions, set_upnp_ns

desc_url = ''
if len(sys.argv) > 1:
   args = sys.argv[1:]
   argn = ''
   for arg in args:
       if arg == '-a':
           set_upnp_actions(True)
       else:
           desc_url = arg

if  desc_url != '':
    set_upnp_ns(0)
    try:
        device = upnp_process_description(desc_url)
    except Exception as e:
        print('parse failed: {0}'.format(e))
        device = None
    if device is None:
        set_upnp_ns(1)
        device = upnp_process_description(desc_url)
    if device is not None:
        upnp_print_schema(device)
        if hasattr(device, 'manufacturer') and device.manufacturer:
            print('Vendor: '+device.manufacturer)
        if hasattr(device, 'model_name') and device.model_name:
            print('Model: '+device.model_name)
        if hasattr(device, 'model_description') and device.model_description:
            print('Description: '+device.model_description)
        if hasattr(device, 'model_number') and device.model_number:
            print('Number: '+device.model_number)
        service = upnp_get_service(device, 'WANCommonInterfaceConfig:1')
        if service is not None:
            print('Service %s (type %s) %s' % (service.id, service.type, service.control_url))
