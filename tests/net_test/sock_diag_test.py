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

  def assertSockDiagMatchesSocket(self, s, diag_msg):
    family = s.getsockopt(net_test.SOL_SOCKET, net_test.SO_DOMAIN)
    self.assertEqual(diag_msg.family, family)

    # TODO: The kernel (at least 3.10) seems only to fill in the first 4 bytes
    # of src and dst in the case of IPv4 addresses. This means we can't just do
    # something like:
    #  self.assertEqual(diag_msg.id.src, self.sock_diag.PaddedAddress(src))
    # because the trailing bytes might not match.
    # This seems like a bug because it might leaks kernel memory contents, but
    # regardless, work around that here.
    addrlen = {AF_INET: 4, AF_INET6: 16}[family]

    src, sport = s.getsockname()[0:2]
    self.assertEqual(diag_msg.id.sport, sport)
    self.assertEqual(diag_msg.id.src[:addrlen],
                     self.sock_diag.RawAddress(src))

    if self.sock_diag.GetDestinationAddress(diag_msg) not in ["0.0.0.0", "::"]:
      dst, dport = s.getpeername()[0:2]
      self.assertEqual(diag_msg.id.dst[:addrlen],
                       self.sock_diag.RawAddress(dst))
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
        self.assertSockDiagMatchesSocket(
            sock,
            self.sock_diag.GetSockDiagForFd(sock))


if __name__ == "__main__":
  unittest.main()
