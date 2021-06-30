#!/usr/bin/env python

import sys
import syslog
import eossdk
import subprocess
import os
import socket
import threading
import json
import re

prefix48Regex = re.compile("^([a-fA-F0-9]{1,4}:){1,3}:\\/48$")

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
        self.sockCommThread = threading.Thread(target=self.handleEvent)
        self.sockCommThread.start()
        
        scriptFilePath = workingDir + '/dhclient-script.py'
        if not os.path.isfile(scriptFilePath):
            syslog.syslog("DHCP-PD Agent: dhclient script file missing ({})".format(scriptFilePath))
            raise ValueError()
        self.pidFilePath = workingDir + '/dhclient.pid'
        leaseFilePath = workingDir + '/dhclient.lease'
        # -6 = ipv6, -P = prefix delegation, -nw = do not wait for ip acquired
        self.args = ['-6', '-P', '-nw', 
                     '-e', 'SOCK_FILE=\"{}\"'.format(sockFilePath),
                     '-sf', scriptFilePath,
                     '-pf', self.pidFilePath,
                     '-lf', leaseFilePath, interface]
        syslog.syslog("DHCP-PD Agent: dhclient socket created")

    def start(self):
        syslog.syslog("DHCP-PD Agent: start dhclient {}".format(' '.join(self.args)))
        dhclientProcess = subprocess.Popen(['dhclient'] + self.args)
        ret = dhclientProcess.wait()
        if ret != 0:
            syslog.syslog("DHCP-PD Agent: unable to start dhclient (return code = {})".format(ret))

    def stop(self):
        syslog.syslog("DHCP-PD Agent: stop dhclient")
        if self.isAlive():
            # release leases and stop dhclient
            dhclientProcess = subprocess.Popen(['dhclient', '-r'] + self.args)
            ret = dhclientProcess.wait()
            if ret != 0:
                syslog.syslog("DHCP-PD Agent: unable to release leases (return code = {})".format(ret))

    def isAlive(self):
        try:
            with open(self.pidFilePath, 'r') as f:
                pid = f.readline()
            if not pid:
                return False
            os.kill(int(pid), 0)
        except Exception:
            return False
        else:
            return True

    def handleEvent(self):
        # retry 3 times before giving up
        for _ in range(3):
            try:
                conn, _ = self.sock.accept()
                while True:
                    data = self.sock.recv(1024)
                    event = json.loads(data)
                    syslog.syslog(event)
                    self.callback(event)
                    if not data:
                        break
                conn.close()
            except Exception as e:
                syslog.syslog("DHCP-PD Agent: dhclient event thread threw exception {}".format(e))
        syslog.syslog("DHCP-PD Agent: dhclient event thread retry exceeded. Stopping.")
        self.stop()


class dhcppd(eossdk.AgentHandler, eossdk.IntfHandler):
    def __init__(self, sdk, dhcpInterface, workingDir):
        self.agentMgr = sdk.get_agent_mgr()
        self.interfaceMgr = sdk.get_intf_mgr()
        self.eapiMgr = sdk.get_eapi_mgr()
        self.tracer = eossdk.Tracer("DHCP-PD-Agent")
        eossdk.AgentHandler.__init__(self, self.agentMgr)
        eossdk.IntfHandler.__init__(self, self.interfaceMgr)
        
        self.dhcpInterface = dhcpInterface
        self.workingDir = workingDir
        self.raPrefixes = dict()
        # for now we only support one prefix per soliciting interface
        # since we do not allow to set client DUID or IAID
        self.delegatedPrefix = None
        self.lock = threading.RLock()

        syslog.syslog("DHCP-PD Agent: constructed")
        self.tracer.trace0("Python Agent constructed")

    def on_initialized(self):
        self.tracer.trace0("Initialized")
        syslog.syslog("DHCP-PD Agent Initialized")

        intf = eossdk.IntfId(self.dhcpInterface)
        if not self.interfaceMgr.exists(intf):
            self.tracer.trace0("Interface {} does not exist".format(self.dhcpInterface))
            syslog.syslog("DHCP-PD Agent: Interface {} does not exist".format(self.dhcpInterface))
            return

        kernelInterface = self.interfaceMgr.kernel_intf_name(intf)
        if not kernelInterface:
            self.tracer.trace0("Interface {} does not have a kernel interface".format(self.dhcpInterface))
            syslog.syslog("DHCP-PD Agent: Interface {} does not have a kernel interfac".format(self.dhcpInterface))
            return

        def callback(event):
            self.on_dhclient_event(event)
        self.dhclient = dhclient(self.workingDir, kernelInterface, callback)
        self.dhclient.start()

    def on_dhclient_event(self, event):
        self.tracer.trace5("Python Agent event {}".format(event))
        with self.lock:
            pass

    @staticmethod
    def parseRaPrefixOption(value):
        # format: <slaId 16 bit hex> <options> => see "ipv6 nd prefix" command for available options
        splitIndex = value.find(' ')
        if splitIndex == -1:
            slaId = value
            return (slaId, None)
        else:
            slaId = value[:splitIndex]
            options = value[splitIndex + 1:]
            return (slaId, options)

    @staticmethod
    def parseDelegatedPrefix48(prefix):
        # We only support /48 delegated prefixes for now
        if not prefix48Regex.match(prefix):
            return None
        doubleColonIndex = prefix.find('::')
        prefixBase =  prefix[:doubleColonIndex]
        groups = prefixBase.count(':') + 1
        # append :0 to make it easy to add SLA ID later
        for _ in range(groups, 3):
            prefixBase.append(':0')
        return prefixBase
        
    @staticmethod
    def prefix48to64(prefix48, slaId):
        return prefix48 + ':' + slaId + '::/64'

    # all options are interpreted as RA interfaces
    def on_agent_option(self, optionName, value):         
        if not value:
            # TODO: remove assigned prefixes
            self.tracer.trace3("RA prefix interface {} deleted".format(optionName))
        else:
            intf = eossdk.IntfId(optionName)
            if not self.interfaceMgr.exists(intf):
                self.tracer.trace1("RA prefix interface {} does not exist. Ignoring.".format(optionName))
                syslog.syslog("DHCP-PD Agent: RA prefix interface {} does not exist. Ignoring.".format(optionName))
                return
            
            slaId, options = dhcppd.parseRaPrefixOption(value)
            try:
                slaIdInt = int(slaId, 16)
                if slaIdInt < 1 or slaIdInt > 0xFFFF:
                    raise ValueError()
            except ValueError:
                self.tracer.trace1("RA prefix interface {} invalid SLA_ID = {}. Expecting 16bit hex value. Ignoring.".format(optionName, value))
                return
            
            if optionName in self.raPrefixes:
                slaIdOld, optionsOld = self.raPrefixes[optionName]
                if slaId != slaIdOld:
                    self.tracer.trace5("RA prefix interface {} remove old SLA_ID {}".format(optionName, slaIdOld))
                    pass # TODO: remove old
                elif options == optionsOld:
                    # slaId and options are equal to old values => do nothing
                    return
                else:
                    self.tracer.trace5("RA prefix interface {} update options \"{}\" => \"{}\"".format(optionName, optionsOld, options))
            
            self.raPrefixes[optionName] = (slaId, options)
            with self.lock:
                if self.delegatedPrefix is not None:
                    # TODO: actually add prefix
                    self.tracer.trace5("RA prefix interface {} add {} {}".format(optionName, slaId, options))

    def on_agent_enabled(self, enabled):
        if not enabled:
            # TODO: remove all assigned prefixes
            self.dhclient.stop()
            self.agentMgr.agent_shutdown_complete_is(True)

        
def main():
    syslog.openlog(ident="DHCP-PD-AGENT", logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)
    sdk = eossdk.Sdk()
    if len(sys.argv) != 3:
        syslog.syslog("DHCP-PD Agent invalid arguments: dhcppd.py <workingDir> <dhcpInterface>")
        sys.exit(-1)
    workingDir = sys.argv[1]
    dhcpInterface = sys.argv[2]
    _ = dhcppd(sdk, dhcpInterface, workingDir)
    sdk.main_loop(sys.argv)
    

if __name__ == "__main__":
    main()