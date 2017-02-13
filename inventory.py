#!/usr/bin/env python

import sys
from rflib import RFConnection, RFOpts


def main():

  if len(sys.argv) < 2:
    print "Usage: inventory.py [-d] <host_exp1> [<host_exp2>...]"
    print "  (Set IPMIUSER & IPMIPASS env first!)"
    return

  hosts = []
  dhcp_output = False
  for host_exp in sys.argv[1:]:
    if host_exp == '-d':
      # TODO: Use proper option parser
      dhcp_output = True
      continue
    hosts.extend(RFOpts.expand_hosts(host_exp))

  for host in hosts:
    conn = RFConnection(host)
    try:
      conn.auth()
      root = conn.get_root()
      system = root.systems[0]
      # Ports are unsorted from the host
      # Collect all the MACs and print the first
      ports = {}
      for intf in system.EthernetInterfaces:
        ports[intf.id] = intf.macaddress
      port_names = ports.keys()
      port_names.sort()
      mac = ports[port_names[0]]
      if dhcp_output:
        print "   host %s {" % host
        print "     hardware ethernet %s;" % mac.lower()
        print "     fixed-address %s;" % host
        print "   }"
        print
      else:
        print "%s\t%s\t%s" % (host, system.sku, mac)
    finally:
      conn.deauth()



if __name__ == '__main__':
  main()
