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
from datetime import datetime

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
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(sockFilePath)
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
                     '-e', 'SOCK_FILE={}'.format(sockFilePath),
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
        try:
            while True:
                data = self.sock.recv(1024)
                event = json.loads(data)
                syslog.syslog(str(event))
                self.callback(event)
                if not data:
                    break
        except Exception as e:
            syslog.syslog("DHCP-PD Agent: dhclient event thread threw exception {}".format(e))


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

        for optionName, value in self.agentMgr.agent_option_iter():
            self.on_agent_option(optionName, value)

    @staticmethod
    def unixTimestampToString(unixTimestamp):
        return datetime.utcfromtimestamp(unixTimestamp).strftime('%Y-%m-%d %H:%M:%S')

    def on_dhclient_event(self, event):
        self.tracer.trace5("Dhclient event {}".format(event))
        reason = event.get('reason')
        if 'new_dhcp6_server_id' in event:
            self.agentMgr.status_set('(A) DUID Server:', str(event['new_dhcp6_server_id']))
        if 'new_ip6_prefix' in event:
            delegatedPrefixStr = str(event['new_ip6_prefix'])
            newDelegatedPrefix = dhcppd.parseDelegatedPrefix48(delegatedPrefixStr)
            if newDelegatedPrefix is None:
                self.tracer.trace1("Dhclient got invalid prefix {}".format(delegatedPrefixStr))
                self.agentMgr.status_set('(B) Delegated Prefix:', 'invalid prefix {}'.format(delegatedPrefixStr))
            else:
                self.agentMgr.status_set('(B) Delegated Prefix:', delegatedPrefixStr)
        if 'new_life_starts' in event and 'new_preferred_life' in event and 'new_max_life' in event:
            lifeStarts = int(event['new_life_starts'])
            self.agentMgr.status_set('(C) Lifetime Starts:', dhcppd.unixTimestampToString(lifeStarts))

            lifePreferred = int(event['new_preferred_life'])
            self.agentMgr.status_set('(D) Lifetime Preferred [s]:', str(lifePreferred))
            self.agentMgr.status_set('(E) Lifetime Preferred Ends:', dhcppd.unixTimestampToString(lifeStarts + lifePreferred))
            
            lifeValid = int(event['new_max_life'])
            self.agentMgr.status_set('(F) Lifetime Valid [s]:', str(lifeValid))
            self.agentMgr.status_set('(G) Lifetime Valid Ends:', dhcppd.unixTimestampToString(lifeStarts + lifeValid))

        if 'new_dhcp6_client_id' in event:
            self.agentMgr.status_set('(H) DUID Client:', str(event['new_dhcp6_client_id']))
        if 'new_iaid' in event:
            self.agentMgr.status_set('(I) IAID:', str(event['new_iaid']))
        if 'new_starts' in event:
            iaStarts = int(event['new_starts'])
            self.agentMgr.status_set('(J) IA Starts:', dhcppd.unixTimestampToString(iaStarts))
            # RFC3633: Recommended values for T1 and T2 are .5 and .8 times the shortest preferred lifetime of the prefix
            if 'new_renew' in event: # IA T1
                # The time at which the requesting router should
                # contact the delegating router from which the
                # prefixes in the IA_PD were obtained to extend the
                # lifetimes of the prefixes delegated to the IA_PD
                iaT1 = int(event['new_renew'])
                self.agentMgr.status_set('(K) IA T1 [s]:', str(iaT1))
                if iaT1 != 0:
                    self.agentMgr.status_set('(K1) IA T1 Ends:', dhcppd.unixTimestampToString(iaStarts + iaT1))
                else:
                    self.agentMgr.status_del('(K1) IA T1 Ends:')
            if 'new_rebind' in event: # IA T2
                # The time at which the requesting router should
                # contact any available delegating router to extend
                # the lifetimes of the prefixes assigned to the IA_PD
                iaT2 = int(event['new_rebind'])
                self.agentMgr.status_set('(L) IA T2 [s]:', str(iaT2))
                if iaT2 != 0:
                    self.agentMgr.status_set('(L1) IA T2 Ends:', dhcppd.unixTimestampToString(iaStarts + iaT2))
                else:
                    self.agentMgr.status_del('(L1) IA T2 Ends:')

        if reason == 'PREINIT6':
            pass # nothing to do
        elif reason in ['BOUND6', 'RENEW6', 'REBIND6']:
            # BOUND6 = We received a DHCPv6 reply with a prefix
            # RENEW6 = The lease was renewed (same prefix)
            # REBIND6 = Bound to a new DHCP server
            if newDelegatedPrefix is not None:
                with self.lock:
                    if self.delegatedPrefix != newDelegatedPrefix:
                        if self.delegatedPrefix is not None:
                            self.removeAllPrefixRAs()
                        self.delegatedPrefix = newDelegatedPrefix
                        self.addPrefixRAsToAll()
        elif reason == 'DEPREF6':
            # if prefered lifetime on our lease is up we get a deprefer message.
            # Since we only support one prefix there is nothing to do
            pass
        elif reason in ['EXPIRE6', 'RELEASE6', 'STOP6']:
            # EXPIRE6 = The lease expires and we failed to obtain a new one
            # RELEASE6 = The client relinquishes the prefix (dhclient -r)
            # STOP6 = Stopping DHCP client with (dhclient -x)
            with self.lock:
                self.removeAllPrefixRAs()
                self.delegatedPrefix = None
        else:
            self.tracer.trace1("Dhclient event {} unknown".format(reason))
    
    # Should be called with lock held
    def removeAllPrefixRAs(self):
        for interface, (slaId, _) in self.raPrefixes:
            self.removePrefixRA(interface, slaId)

    def addPrefixRAsToAll(self):
        for interface, (slaId, options) in self.raPrefixes.items():
            self.addPrefixRA(interface, slaId, options)

    # Should be called with lock held
    def addPrefixRA(self, interface, slaId, options):
        if options is None:
            ndRaCommand = 'ipv6 nd prefix {}'.format(dhcppd.prefix48to64(self.delegatedPrefix, slaId))
        else:
            ndRaCommand = 'ipv6 nd prefix {} {}'.format(dhcppd.prefix48to64(self.delegatedPrefix, slaId), options)
        self.raPrefixes[interface] = (slaId, options)
        interfaceCommand = 'interface {}'.format(interface)
        result = self.eapiMgr.run_config_cmds([interfaceCommand, ndRaCommand])
        if result.success():
            self.tracer.trace5("Successfully configured RA prefix interface {} ({})".format(interface, ndRaCommand))
            syslog.syslog("DHCP-PD Agent: Successfully configured RA prefix interface {} ({})".format(interface, ndRaCommand))
        else:
            self.tracer.trace1("Error configuring RA prefix interface {} ({}): {}".format(interface, ndRaCommand, result.error_message()))
            syslog.syslog("DHCP-PD Agent: Error configuring RA prefix interface {} ({}): {}".format(interface, ndRaCommand, result.error_message()))


    # Should be called with lock held
    def removePrefixRA(self, interface, slaId):
        del self.raPrefixes[interface]
        ndRaCommand = 'no ipv6 nd prefix {}'.format(dhcppd.prefix48to64(self.delegatedPrefix, slaId))
        interfaceCommand = 'interface {}'.format(interface)
        result = self.eapiMgr.run_config_cmds([interfaceCommand, ndRaCommand])
        if result.success():
            self.tracer.trace5("Successfully removed prefix from {} ({})".format(interface, ndRaCommand))
            syslog.syslog("DHCP-PD Agent: Successfully removed prefix from interface {} ({})".format(interface, ndRaCommand))
        else:
            self.tracer.trace1("Error removing prefix from {} ({}): {}".format(interface, ndRaCommand, result.error_message()))
            syslog.syslog("DHCP-PD Agent: Error removing prefix from {} ({}): {}".format(interface, ndRaCommand, result.error_message()))

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
    def on_agent_option(self, interface, value):         
        if not value:
            with self.lock:
                self.removePrefixRA(interface, self.raPrefixes[interface])
            self.tracer.trace3("RA prefix interface {} deleted".format(interface))
        else:
            try:
                interfaceId = eossdk.IntfId(interface)
            except Exception as e:
                syslog.syslog("DHCP-PD Agent: option invalid: {}. Ignoring.".format(str(e)))
                self.tracer.trace1("option invalid: {}. Ignoring.".format(str(e)))
                return

            if not self.interfaceMgr.exists(interfaceId):
                self.tracer.trace1("RA prefix interface {} does not exist. Ignoring.".format(interface))
                syslog.syslog("DHCP-PD Agent: RA prefix interface {} does not exist. Ignoring.".format(interface))
                return
            
            slaId, options = dhcppd.parseRaPrefixOption(value)
            try:
                slaIdInt = int(slaId, 16)
                if slaIdInt < 1 or slaIdInt > 0xFFFF:
                    raise ValueError()
            except ValueError:
                self.tracer.trace1("RA prefix interface {} invalid SLA_ID = {}. Expecting 16bit hex value. Ignoring.".format(interface, value))
                return
            
            if interface in self.raPrefixes:
                slaIdOld, optionsOld = self.raPrefixes[interface]
                if slaId != slaIdOld:
                    # SLA_ID changed
                    self.tracer.trace5("RA prefix interface {} remove old prefix with SLA_ID {}".format(interface, slaIdOld))
                    with self.lock:
                        self.removePrefixRA(interface, slaIdOld)
                elif options == optionsOld:
                    # slaId and options are equal to old values => do nothing
                    return
                else:
                    # options updated
                    self.tracer.trace5("RA prefix interface {} update options \"{}\" => \"{}\"".format(interface, optionsOld, options))
            
            with self.lock:
                if self.delegatedPrefix is not None:
                    with self.lock:
                        self.addPrefixRA(interface, slaId, options)
                    self.tracer.trace5("RA prefix interface {} add {} {}".format(interface, slaId, options))

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