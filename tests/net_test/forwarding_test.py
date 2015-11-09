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

import itertools
import random
import unittest

from socket import *

import iproute
import multinetwork_base
import net_test
import packets


class ForwardingTest(multinetwork_base.MultiNetworkBaseTest):

  TCP_TIME_WAIT = 6

  def ForwardBetweenInterfaces(self, enabled, iface1, iface2):
    for iif, oif in itertools.permutations([iface1, iface2]):
      self.iproute.IifRule(6, enabled, self.GetInterfaceName(iif),
                           self._TableForNetid(oif), self.PRIORITY_IIF)

  def setUp(self):
    self.SetSysctl("/proc/sys/net/ipv6/conf/all/forwarding", 1)

  def tearDown(self):
    self.SetSysctl("/proc/sys/net/ipv6/conf/all/forwarding", 0)

  def CheckForwardingCrash(self, netid, iface1, iface2):
    listenport = packets.RandomPort()
    listensocket = net_test.IPv6TCPSocket()
    listensocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listensocket.bind(("::", listenport))
    listensocket.listen(100)
    self.SetSocketMark(listensocket, netid)

    version = 6
    remoteaddr = self.GetRemoteAddress(version)
    myaddr = self.MyAddress(version, netid)

    desc, syn = packets.SYN(listenport, version, remoteaddr, myaddr)
    synack_desc, synack = packets.SYNACK(version, myaddr, remoteaddr, syn)
    msg = "Sent %s, expected %s" % (desc, synack_desc)
    reply = self._ReceiveAndExpectResponse(netid, syn, synack, msg)

    establishing_ack = packets.ACK(version, remoteaddr, myaddr, reply)[1]
    self.ReceivePacketOn(netid, establishing_ack)
    accepted, peer = listensocket.accept()
    remoteport = accepted.getpeername()[1]

    accepted.close()
    desc, fin = packets.FIN(version, myaddr, remoteaddr, establishing_ack)
    self.ExpectPacketOn(netid, msg + ": expecting %s after close" % desc, fin)

    desc, finack = packets.FIN(version, remoteaddr, myaddr, fin)
    self.ReceivePacketOn(netid, finack)

    # Check our socket is now in TIME_WAIT.
    sockets = self.ReadProcNetSocket("tcp6")
    mysrc = "%s:%04X" % (net_test.FormatSockStatAddress(myaddr), listenport)
    mydst = "%s:%04X" % (net_test.FormatSockStatAddress(remoteaddr), remoteport)
    state = None
    sockets = [s for s in sockets if s[0] == mysrc and s[1] == mydst]
    self.assertEquals(1, len(sockets))
    self.assertEquals("%02X" % self.TCP_TIME_WAIT, sockets[0][2])

    # Remove our IP address.
    try:
      self.iproute.DelAddress(myaddr, 64, self.ifindices[netid])

      self.ReceivePacketOn(iface1, finack)
      self.ReceivePacketOn(iface1, establishing_ack)
      self.ReceivePacketOn(iface1, establishing_ack)
      # No crashes? Good.

    finally:
      # Put back our IP address.
      self.SendRA(netid)
      listensocket.close()

  def testCrash(self):
    # Run the test a few times as it doesn't crash/hang the first time.
    for netids in itertools.permutations(self.tuns):
      # Pick an interface to send traffic on and two to forward traffic between.
      netid, iface1, iface2 = random.sample(netids, 3)
      self.ForwardBetweenInterfaces(True, iface1, iface2)
      try:
        self.CheckForwardingCrash(netid, iface1, iface2)
      finally:
        self.ForwardBetweenInterfaces(False, iface1, iface2)


if __name__ == "__main__":
  unittest.main()
