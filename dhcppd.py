import sys
import syslog
import eossdk
import subprocess
import os
import socket
import threading
import json

class dhclient:
    def __init__(self, workingDir, interface, callback):
        if not os.path.isdir(workingDir):
            syslog.syslog("DHCP-PD Agent: dhclient working directory does not exist")
            raise ValueError()
        sockFilePath = workingDir + '/sock'
        self.sockFilePath = sockFilePath
        try:
            os.unlink(sockFilePath)
        except OSError as e:
            if os.path.exists(sockFilePath):
                raise e
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(sockFilePath)
        self.sock.listen(1)
        self.callback = callback
        self.interface = interface
        self.sockCommThread = threading.Thread(target=self.handleEvent, args=(self))
        self.sockCommThread.start()
        
        self.scriptFilePath = workingDir + '/dhclient-script.py'
        if not os.path.isfile(self.scriptFilePath):
            syslog.syslog("DHCP-PD Agent: dhclient script file missing ({})".format(self.scriptFilePath))
            raise ValueError()
        self.pidFilePath = workingDir + '/dhclient.pid'
        self.leaseFilePath = workingDir + '/dhclient.lease'
        syslog.syslog("DHCP-PD Agent: dhclient Socket Created")

    def start(self):
        syslog.syslog("DHCP-PD Agent: start")

    def stop(self):
        syslog.syslog("DHCP-PD Agent: stop")
        # release leases and stop
        pass

    def handleEvent(self):
        while True:
            conn, _ = self.sock.accept()
            with conn:
                while True:
                    data = self.sock.recv(1024)
                    event = json.loads(data)
                    syslog.syslog(event)
                    self.callback(event)
                    if not data:
                        break
            # TODO: check if dhclient is still alive



class dhcppd(eossdk.AgentHandler, eossdk.IntfHandler):
    def __init__(self, sdk, dhcpInterface, workingDir):
        self.agentMgr = sdk.get_agent_mgr()
        self.interfaceMgr = sdk.get_intf_mgr()
        self.tracer = eossdk.Tracer("DHCP-PD-Agent")
        eossdk.AgentHandler.__init__(self, self.agentMgr)
        eossdk.IntfHandler.__init__(self, self.interfaceMgr)

        for intf in self.interfaceMgr.intf_iter():
            syslog.syslog(intf)
        # TODO: check if interface exists
        self.dhcpInterface = dhcpInterface
        self.workingDir = workingDir
        self.slaIds = dict()
        self.prefix = None

        syslog.syslog("DHCP-PD Agent: constructed")
        self.tracer.trace0("Python Agent constructed")

    def on_dhclient_event(self, event):
        self.tracer.trace5("Python Agent event {}".format(event))

    def on_initialized(self):
        self.tracer.trace0("Initialized")
        syslog.syslog("DHCP-PD Agent Initialized")
        self.agentMgr.status_set("Status: ", "Initializing")

        def callback(event):
            self.on_dhclient_event(event)
        self.dhclient = dhclient(self.workingDir, self.dhcpInterface, callback)
        self.dhclient.start()
        self.agentMgr.status_set("Status: ", "Running")

    # all options are interpreted as interfaces
    def on_agent_option(self, optionName, value):                
        if not value:
            self.tracer.trace3("Prefix interface {} deleted".format(optionName))
            # TODO: remove assigned prefixes
        else:
            # TODO: check if interface exists
            if optionName in self.slaIds:
                oldValue = self.slaIds[optionName]
                if value != oldValue:
                    pass # TODO: remove old
            try:
                slaIdInt = int(value, 16)
                if slaIdInt < 1 or slaIdInt > 0xFFFF:
                    raise ValueError()
            except ValueError:
                self.tracer.trace1("Prefix interface {} invalid SLA_ID = {}. Expecting 16bit hex value. Ignoring.".format(optionName, value))
                return
            self.slaIds[optionName] = value
            # TODO: actually add prefix

    def on_agent_enabled(self, enabled):
        if not enabled:
            # cleanup
            self.dhclient.stop()
            self.agentMgr.agent_shutdown_complete_is(True)

        
def main():
    syslog.openlog(ident="DHCP-PD-AGENT", logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)
    sdk = eossdk.Sdk()
    if len(sys.argv) != 2:
        syslog.syslog("DHCP-PD Agent invalid arguments: dhcppd.py <workingDir> <dhcpInterface>")
        sys.exit(-1)
    workingDir = sys.argv[0]
    dhcpInterface = sys.argv[1]
    _ = dhcppd(sdk, dhcpInterface, workingDir)
    sdk.main_loop(sys.argv)
    

if __name__ == "__main__":
    main()