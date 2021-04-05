#!/usr/bin/env python3
import sys
from util.upnptools import discovery_channel, set_upnp_actions

default_bind_addr = ('192.168.1.55', 2600)
bind_addr = ''
if len(sys.argv) > 1:
   args = sys.argv[1:]
   argn = ''
   for arg in args:
       if arg == '-a':
           set_upnp_actions(True)
       else:
           bind_addr = arg

if  bind_addr != '':
    default_bind_addr = (bind_addr, 2600)
discovery_channel(default_bind_addr)
