#!/usr/bin/env python3

import os
import sys
import syslog
import socket
import json
import re

event_regex = 'pid|reason|interface|((old|new)_(iaid|rebind|dhcp6_(server|client)_id|starts|renew|ip6_prefix|max_life|preferred_life|life_starts))'

syslog.openlog(ident="DHCLIENT-DHCP-PD", logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)

def run(environ):
    sockFilePath = environ['SOCK_FILE']
    if sockFilePath is None:
        syslog.syslog("Socket file path missing! (-e SOCK_PATH=...)")
        return
    syslog.syslog(str(environ))
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(sockFilePath)
        events = { k: v for k, v in environ.items() if re.match(event_regex, k)}
        sock.sendmsg(json.dumps(events))
        sock.close()
    except Exception as e:
        syslog.syslog(str(e))
        sys.exit(-1)
        
    

run(os.environ)