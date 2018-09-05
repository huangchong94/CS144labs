# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
This is an L2 learning switch written directly against the OpenFlow library.
It is derived from one written live for an SDN crash course.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
import pox.lib.packet.icmp as icmp
from pox.lib.packet.arp import arp
from pox.lib.packet.udp import udp
from pox.lib.packet.dns import dns
from pox.lib.addresses import IPAddr, EthAddr


import time
import code
import os
import struct
import sys

log = core.getLogger()
FLOOD_DELAY = 5
#default location /home/ubuntu/cs144_lab3/IP_CONFIG
IPCONFIG_FILE = './IP_CONFIG'
IP_SETTING={}
RTABLE = []
ROUTER_IP={}

#Topology is fixed 
#sw0-eth1:server1-eth0 sw0-eth2:server2-eth0 sw0-eth3:client

class RouterInfo(Event):
  '''Event to raise upon the information about an openflow router is ready'''

  def __init__(self, info, rtable):
    Event.__init__(self)
    self.info = info
    self.rtable = rtable


class OFHandler (EventMixin):
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent
    self.sw_info = {}
    self.connection.send(of.ofp_switch_config(miss_send_len = 20000))
    # self.connection.send(of.ofp_switch_config(miss_send_len = 65535))
    for port in connection.features.ports:
        intf_name = port.name.split('-')
        if(len(intf_name) < 2):
          continue
        else:
          intf_name = intf_name[1]
        if intf_name in ROUTER_IP.keys():
          self.sw_info[intf_name] = (ROUTER_IP[intf_name], port.hw_addr.toStr(), '10Gbps', port.port_no)
    self.rtable = RTABLE
    # We want to hear Openflow PacketIn messages, so we listen
    self.listenTo(connection)
    self.listenTo(core.cs144_srhandler)
    core.cs144_ofhandler.raiseEvent(RouterInfo(self.sw_info, self.rtable))

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """
    pkt = event.parse()
    raw_packet = pkt.raw
    core.cs144_ofhandler.raiseEvent(SRPacketIn(raw_packet, event.port))
    msg = of.ofp_packet_out()
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)


  def _handle_SRPacketOut(self, event):
    msg = of.ofp_packet_out()
    new_packet = event.pkt
    msg.actions.append(of.ofp_action_output(port=event.port))
    msg.buffer_id = -1
    msg.in_port = of.OFPP_NONE
    msg.data = new_packet
    self.connection.send(msg)

class SRPacketIn(Event):
  '''Event to raise upon a receive a packet_in from openflow'''

  def __init__(self, packet, port):
    Event.__init__(self)
    self.pkt = packet
    self.port = port

# Credits to:
# https://github.com/noxrepo/pox/blob/master/pox/nom_l2_switch_controller/learning_switch.py
class LearningSwitch (EventMixin):
  def __init__(self, connection, transparent):
    self.connection = connection
    self.transparent = transparent
    self.mac_to_port = {}
    self.listenTo(connection)

  def _handle_PacketIn(self, event):
    def flood():
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      event.connection.send(msg)

    packet = event.parse()
    self.mac_to_port[packet.src] = event.port
    if packet.dst.isMulticast():
        flood()
    else:
      if packet.dst not in self.mac_to_port:
        log.debug("port for %s unknown -- flooding" % (packet.dst,))
        flood()
      else:
        port = self.mac_to_port[packet.dst]
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(in_port=event.port,
                                 dl_dst=EthAddr(packet.dst))
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port=port))
        msg.buffer_id = event.ofp.buffer_id
        event.connection.send(msg)
    return

class cs144_ofhandler (EventMixin):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  _eventMixin_events = set([SRPacketIn, RouterInfo])

  def __init__ (self, transparent):
    EventMixin.__init__(self)
    self.listenTo(core.openflow)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    if( event.dpid == 1):
      log.info("Creating learning switch %s" % dpidToStr(event.dpid))
      LearningSwitch(event.connection, self.transparent)
    else:
      OFHandler(event.connection, self.transparent)


def get_ip_setting():
  if (not os.path.isfile(IPCONFIG_FILE)):
    return -1
  f = open(IPCONFIG_FILE, 'r')
  for line in f:
    if(len(line.split()) == 0):
      break
    name, ip = line.split()
    if ip == "<ELASTIC_IP>":
      log.info("ip configuration is not set, please put your Elastic IP addresses into %s" % IPCONFIG_FILE)
      sys.exit(2)
    #print name, ip
    IP_SETTING[name] = ip

  RTABLE.append( ('%s' % IP_SETTING['client'], '%s' % IP_SETTING['client'], '255.255.255.255', 'eth1') )
  RTABLE.append( ('%s' % IP_SETTING['server1'], '%s' % IP_SETTING['server1'], '255.255.255.255', 'eth2') )
  RTABLE.append( ('%s' % IP_SETTING['server2'], '%s' % IP_SETTING['server2'], '255.255.255.255', 'eth2') )


  ROUTER_IP['eth1'] = '%s' % IP_SETTING['sw0-eth1']
  ROUTER_IP['eth2'] = '%s' % IP_SETTING['sw0-eth2']
  return 0


def launch (transparent=False):
  """
  Starts an Simple Router Topology
  """    
  core.registerNew(cs144_ofhandler, str_to_bool(transparent))
  
  r = get_ip_setting()
  if r == -1:
    log.debug("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)
    sys.exit(2)
  else:
    log.debug('*** ofhandler: Successfully loaded ip settings for hosts\n %s\n' % IP_SETTING)
