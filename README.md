# EOS DHCP-PD agent

This EOS agent allows to request a prefix from a DHCPv6 server [RFC3633](https://tools.ietf.org/html/rfc3633) and assign it to an interface 
to send out RAs to configure ipv6 addresses via SLAAC [RFC4862](https://datatracker.ietf.org/doc/html/rfc4862).

We only support one /48 delegated prefix. This prefix can be assigned to any ipv6 enabled interface with an SLA id to create a /64 prefix for SLAAC.
We support changing the RA prefix interface configuration while the agent is running, e.g. adding additional interfaces or changing the SLA id.

## Usage

1. Copy content to switch, e.g. `/mnt/flash/eos-dhcp-pd`
2. For EOS release < 4.26.0 only: Copy sysdb file or create symlink, e.g. 
```
ln -s /mnt/flash/eos-dhcp-pd/dhcppd.sysdb /usr/lib/SysdbMountProfiles/dhcppd.py
```
3. Start daemon from cli, e.g.
```
!
daemon DhcpPdEthernet1
   exec /mnt/flash/eos-dhcp-pd/dhcppd.py /mnt/flash/eos-dhcp-pd Ethernet1
   option Vlan1 value 1
   no shutdown
!
```
The example above sends DHCP-PD requests on Ethernet1 and assigns a /64 prefix to Vlan1 with SLA id 0x1. 
For example if the /48 prefix received from the DHCP server is `fc00::/48` the resulting RA prefix on Vlan1 will be `fc00:0:0:1::/64`.
You can add additional arguments to the option. The format is:
```
<slaId 16 bit hex> <arguments>
```
See "ipv6 nd prefix" command for available arguments
