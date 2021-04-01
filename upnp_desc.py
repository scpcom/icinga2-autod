#!/usr/bin/env python
import sys
from util.upnptools import upnp_process_description, upnp_print_schema

if len(sys.argv) > 1:
    try:
        device = upnp_process_description(sys.argv[1])
    except Exception as e:
        print('parse failed: {0}'.format(e))
        device = None
    if device is not None:
        upnp_print_schema(device)
        print 'Vendor: '+device.manufacturer
        print 'Model: '+device.model_name
        print 'Description: '+device.model_description
