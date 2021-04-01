#!/usr/bin/env python
import sys
from util.upnptools import discovery_channel

default_bind_addr = ('192.168.1.55', 2600)
if len(sys.argv) > 1:
    default_bind_addr = (sys.argv[1], 2600)
discovery_channel(default_bind_addr)
