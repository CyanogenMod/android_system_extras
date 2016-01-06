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
from socket import *
import time
import unittest

import csocket
import cstruct
import multinetwork_base
import net_test
import packets
import sock_diag


NUM_SOCKETS = 100

ALL_NON_TIME_WAIT = 0xffffffff & ~(1 << sock_diag.TCP_TIME_WAIT)


class SockDiagTest(multinetwork_base.MultiNetworkBaseTest):

  @staticmethod
  def _CreateLotsOfSockets():
    # Dict mapping (addr, sport, dport) tuples to socketpairs.
    socketpairs = {}
    for i in xrange(NUM_SOCKETS):
      family, addr = random.choice([(AF_INET, "127.0.0.1"), (AF_INET6, "::1")])
      socketpair = net_test.CreateSocketPair(family, SOCK_STREAM, addr)
      sport, dport = (socketpair[0].getsockname()[1],
                      socketpair[1].getsockname()[1])
      socketpairs[(addr, sport, dport)] = socketpair
    return socketpairs

  def setUp(self):
    self.sock_diag = sock_diag.SockDiag()
    self.socketpairs = self._CreateLotsOfSockets()

  def tearDown(self):
    [s.close() for socketpair in self.socketpairs.values() for s in socketpair]

  def testFixupDiagMsg(self):
    src = "0a00fa02303030312030312038302031"
    dst = "0808080841414141414141416f0a3230"
    cookie = "4078678100000000"
    sockid = sock_diag.InetDiagSockId((47436, 32069,
                                       src.decode("hex"), dst.decode("hex"), 0,
                                       cookie.decode("hex")))
    msg4 = sock_diag.InetDiagMsg((AF_INET, IPPROTO_TCP, 0,
                                  sock_diag.TCP_SYN_RECV, sockid,
                                  980, 123, 456, 789, 5555))
    # Make a copy, cstructs are mutable.
    msg6 = sock_diag.InetDiagMsg(msg4.Pack())
    msg6.family = AF_INET6

    fixed6 = sock_diag.InetDiagMsg(msg6.Pack())
    self.sock_diag.FixupDiagMsg(fixed6)
    self.assertEquals(msg6.Pack(), fixed6.Pack())

    fixed4 = sock_diag.InetDiagMsg(msg4.Pack())
    self.sock_diag.FixupDiagMsg(fixed4)
    msg4.id.src = src.decode("hex")[:4] + 12 * "\x00"
    msg4.id.dst = dst.decode("hex")[:4] + 12 * "\x00"
    self.assertEquals(msg4.Pack(), fixed4.Pack())

  def assertSockDiagMatchesSocket(self, s, diag_msg):
    family = s.getsockopt(net_test.SOL_SOCKET, net_test.SO_DOMAIN)
    self.assertEqual(diag_msg.family, family)

    self.sock_diag.FixupDiagMsg(diag_msg)

    src, sport = s.getsockname()[0:2]
    self.assertEqual(diag_msg.id.src, self.sock_diag.PaddedAddress(src))
    self.assertEqual(diag_msg.id.sport, sport)

    if self.sock_diag.GetDestinationAddress(diag_msg) not in ["0.0.0.0", "::"]:
      dst, dport = s.getpeername()[0:2]
      self.assertEqual(diag_msg.id.dst, self.sock_diag.PaddedAddress(dst))
      self.assertEqual(diag_msg.id.dport, dport)
    else:
      assertRaisesErrno(errno.ENOTCONN, s.getpeername)

  def testFindsAllMySockets(self):
    sockets = self.sock_diag.DumpAllInetSockets(IPPROTO_TCP,
                                                states=ALL_NON_TIME_WAIT)
    self.assertGreaterEqual(len(sockets), NUM_SOCKETS)

    # Find the cookies for all of our sockets.
    cookies = {}
    for diag_msg, attrs in sockets:
      addr = self.sock_diag.GetSourceAddress(diag_msg)
      sport = diag_msg.id.sport
      dport = diag_msg.id.dport
      if (addr, sport, dport) in self.socketpairs:
        cookies[(addr, sport, dport)] = diag_msg.id.cookie
      elif (addr, dport, sport) in self.socketpairs:
        cookies[(addr, sport, dport)] = diag_msg.id.cookie

    # Did we find all the cookies?
    self.assertEquals(2 * NUM_SOCKETS, len(cookies))

    socketpairs = self.socketpairs.values()
    random.shuffle(socketpairs)
    for socketpair in socketpairs:
      for sock in socketpair:
        # Check that we can find a diag_msg by scanning a dump.
        self.assertSockDiagMatchesSocket(
            sock,
            self.sock_diag.FindSockDiagFromFd(sock))
        cookie = self.sock_diag.FindSockDiagFromFd(sock).id.cookie

        # Check that we can find a diag_msg once we know the cookie.
        req = self.sock_diag.DiagReqFromSocket(sock)
        req.id.cookie = cookie
        req.states = 1 << diag_msg.state
        diag_msg, attrs = self.sock_diag.GetSockDiag(req)
        self.assertSockDiagMatchesSocket(sock, diag_msg)


if __name__ == "__main__":
  unittest.main()
