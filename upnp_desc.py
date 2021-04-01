#!/usr/bin/env python3
import sys
from util.upnptools import upnp_process_description, upnp_print_schema, set_upnp_ns

if len(sys.argv) > 1:
    set_upnp_ns(0)
    try:
        device = upnp_process_description(sys.argv[1])
    except Exception as e:
        print('parse failed: {0}'.format(e))
        device = None
    if device is None:
        set_upnp_ns(1)
        device = upnp_process_description(sys.argv[1])
    if device is not None:
        upnp_print_schema(device)
        print('Vendor: '+device.manufacturer)
        print('Model: '+device.model_name)
        if device.model_description:
            print('Description: '+device.model_description)
        if device.model_number:
            print('Number: '+device.model_number)
