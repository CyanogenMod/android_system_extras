#!/usr/bin/python
#
# Copyright 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import errno
import random
from socket import *  # pylint: disable=wildcard-import
import time
import unittest

from scapy import all as scapy

import multinetwork_base
import net_test


RTMGRP_NEIGH = 4

NUD_INCOMPLETE = 0x01
NUD_REACHABLE = 0x02
NUD_STALE = 0x04
NUD_DELAY = 0x08
NUD_PROBE = 0x10
NUD_FAILED = 0x20
NUD_PERMANENT = 0x80


# TODO: Support IPv4.
class NeighbourTest(multinetwork_base.MultiNetworkBaseTest):

  # Set a 100-ms retrans timer so we can test for ND retransmits without
  # waiting too long. Apparently this cannot go below 500ms.
  RETRANS_TIME_MS = 500

  # This can only be in seconds, so 1000 is the minimum.
  DELAY_TIME_MS = 1000

  # Unfortunately, this must be above the delay timer or the kernel ND code will
  # not behave correctly (e.g., go straight from REACHABLE into DELAY). This is
  # is fuzzed by the kernel from 0.5x to 1.5x of its value, so we need a value
  # that's 2x the delay timer.
  REACHABLE_TIME_MS = 2 * DELAY_TIME_MS

  @classmethod
  def setUpClass(cls):
    super(NeighbourTest, cls).setUpClass()
    for netid in cls.tuns:
      iface = cls.GetInterfaceName(netid)
      # This can't be set in an RA.
      cls.SetSysctl(
          "/proc/sys/net/ipv6/neigh/%s/delay_first_probe_time" % iface,
          cls.DELAY_TIME_MS / 1000)

  def setUp(self):
    super(NeighbourTest, self).setUp()

    self.sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)
    self.sock.bind((0, RTMGRP_NEIGH))
    net_test.SetNonBlocking(self.sock)

    for netid in self.tuns:
      self.SendRA(netid,
                  retranstimer=self.RETRANS_TIME_MS,
                  reachabletime=self.REACHABLE_TIME_MS)

    self.netid = random.choice(self.tuns.keys())
    self.ifindex = self.ifindices[self.netid]

  def GetNeighbour(self, addr):
    version = 6 if ":" in addr else 4
    for msg, args in self.iproute.DumpNeighbours(version):
      if args["NDA_DST"] == addr:
        return msg, args

  def GetNdEntry(self, addr):
    return self.GetNeighbour(addr)

  def CheckNoNdEvents(self):
    self.assertRaisesErrno(errno.EAGAIN, self.sock.recvfrom, 4096, MSG_PEEK)

  def assertNeighbourState(self, state, addr):
    self.assertEquals(state, self.GetNdEntry(addr)[0].state)

  def assertNeighbourAttr(self, addr, name, value):
    self.assertEquals(value, self.GetNdEntry(addr)[1][name])

  def ExpectNeighbourNotification(self, addr, state, attrs=None):
    msg = self.sock.recv(4096)
    msg, actual_attrs = self.iproute.ParseNeighbourMessage(msg)
    self.assertEquals(addr, actual_attrs["NDA_DST"])
    self.assertEquals(state, msg.state)
    if attrs:
      for name in attrs:
        self.assertEquals(attrs[name], actual_attrs[name])

  def ExpectUnicastProbe(self, addr):
    version = 6 if ":" in addr else 4
    if version == 6:
      expected = (
          scapy.IPv6(src=self.MyLinkLocalAddress(self.netid), dst=addr) /
          scapy.ICMPv6ND_NS(tgt=addr) /
          scapy.ICMPv6NDOptSrcLLAddr(lladdr=self.MyMacAddress(self.netid))
      )
      self.ExpectPacketOn(self.netid, "Unicast probe", expected)
    else:
      raise NotImplementedError

  def ReceiveUnicastAdvertisement(self, addr, mac):
    version = 6 if ":" in addr else 4
    if version == 6:
      packet = (
          scapy.Ether(src=mac, dst=self.MyMacAddress(self.netid)) /
          scapy.IPv6(src=addr, dst=self.MyLinkLocalAddress(self.netid)) /
          scapy.ICMPv6ND_NA(tgt=addr, S=1, O=0) /
          scapy.ICMPv6NDOptDstLLAddr(lladdr=mac)
      )
      self.ReceiveEtherPacketOn(self.netid, packet)
    else:
      raise NotImplementedError

  def MonitorSleepMs(self, interval, addr):
    slept = 0
    while slept < interval:
      sleep_ms = min(100, interval - slept)
      time.sleep(sleep_ms / 1000.0)
      slept += sleep_ms
      print self.GetNdEntry(addr)

  def MonitorSleep(self, intervalseconds, addr):
    self.MonitorSleepMs(interval * 1000, addr)

  def SleepMs(self, ms):
    time.sleep(ms / 1000.0)

  def testNotifications(self):
    router4 = self._RouterAddress(self.netid, 4)
    router6 = self._RouterAddress(self.netid, 6)
    self.assertNeighbourState(NUD_PERMANENT, router4)
    self.assertNeighbourState(NUD_STALE, router6)

    # Send a packet and check that we go into DELAY.
    routing_mode = random.choice(["mark", "oif", "uid"])
    s = self.BuildSocket(6, net_test.UDPSocket, self.netid, routing_mode)
    s.connect((net_test.IPV6_ADDR, 53))
    s.send(net_test.UDP_PAYLOAD)
    self.assertNeighbourState(NUD_DELAY, router6)

    # Wait for the probe interval, then check that we're in PROBE, and that the
    # kernel has notified us.
    self.SleepMs(self.DELAY_TIME_MS)
    self.ExpectNeighbourNotification(router6, NUD_PROBE)
    self.assertNeighbourState(NUD_PROBE, router6)
    self.ExpectUnicastProbe(router6)

    # Respond to the NS and verify we're in REACHABLE again.
    self.ReceiveUnicastAdvertisement(router6, self.RouterMacAddress(self.netid))
    self.assertNeighbourState(NUD_REACHABLE, router6)

    # Wait until the reachable time has passed, and verify we're in STALE.
    self.SleepMs(self.REACHABLE_TIME_MS * 1.5)
    self.assertNeighbourState(NUD_STALE, router6)
    self.ExpectNeighbourNotification(router6, NUD_STALE)

    # Send a packet, and verify we go into DELAY and then to PROBE.
    s.send(net_test.UDP_PAYLOAD)
    self.assertNeighbourState(NUD_DELAY, router6)
    self.SleepMs(self.DELAY_TIME_MS)
    self.assertNeighbourState(NUD_PROBE, router6)
    self.ExpectNeighbourNotification(router6, NUD_PROBE)

    # Wait for the probes to time out, and expect a FAILED notification.
    self.assertNeighbourAttr(router6, "NDA_PROBES", 1)
    self.ExpectUnicastProbe(router6)

    self.SleepMs(self.RETRANS_TIME_MS)
    self.ExpectUnicastProbe(router6)
    self.assertNeighbourAttr(router6, "NDA_PROBES", 2)

    self.SleepMs(self.RETRANS_TIME_MS)
    self.ExpectUnicastProbe(router6)
    self.assertNeighbourAttr(router6, "NDA_PROBES", 3)

    self.SleepMs(self.RETRANS_TIME_MS)
    self.assertNeighbourState(NUD_FAILED, router6)
    self.ExpectNeighbourNotification(router6, NUD_FAILED, {"NDA_PROBES": 3})

  def testRepeatedProbes(self):
    router4 = self._RouterAddress(self.netid, 4)
    router6 = self._RouterAddress(self.netid, 6)
    routermac = self.RouterMacAddress(self.netid)
    self.assertNeighbourState(NUD_PERMANENT, router4)
    self.assertNeighbourState(NUD_STALE, router6)

    def ForceProbe(addr, mac):
      self.iproute.UpdateNeighbour(6, addr, None, self.ifindex, NUD_PROBE)
      self.assertNeighbourState(NUD_PROBE, addr)
      self.SleepMs(1)  # TODO: Why is this necessary?
      self.assertNeighbourState(NUD_PROBE, addr)
      self.ExpectUnicastProbe(addr)
      self.ReceiveUnicastAdvertisement(addr, mac)
      self.assertNeighbourState(NUD_REACHABLE, addr)

    for _ in xrange(5):
      ForceProbe(router6, routermac)


if __name__ == "__main__":
  unittest.main()
