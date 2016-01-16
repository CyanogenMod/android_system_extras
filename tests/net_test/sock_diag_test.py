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

from errno import *
import os
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
import threading


NUM_SOCKETS = 100
NO_BYTECODE = ""

# TODO: Backport SOCK_DESTROY and delete this.
HAVE_SOCK_DESTROY = net_test.LINUX_VERSION >= (4, 4)


class SockDiagBaseTest(multinetwork_base.MultiNetworkBaseTest):

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

  def assertSocketClosed(self, sock):
    self.assertRaisesErrno(ENOTCONN, sock.getpeername)

  def assertSocketConnected(self, sock):
    sock.getpeername()  # No errors? Socket is alive and connected.

  def assertSocketsClosed(self, socketpair):
    for sock in socketpair:
      self.assertSocketClosed(sock)


class SockDiagTest(SockDiagBaseTest):

  def setUp(self):
    super(SockDiagTest, self).setUp()
    self.sock_diag = sock_diag.SockDiag()
    self.socketpairs = {}

  def tearDown(self):
    [s.close() for socketpair in self.socketpairs.values() for s in socketpair]
    super(SockDiagTest, self).tearDown()

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
      assertRaisesErrno(ENOTCONN, s.getpeername)

  def testFindsAllMySockets(self):
    self.socketpairs = self._CreateLotsOfSockets()
    sockets = self.sock_diag.DumpAllInetSockets(IPPROTO_TCP, NO_BYTECODE)
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
        diag_msg = self.sock_diag.GetSockDiag(req)
        self.assertSockDiagMatchesSocket(sock, diag_msg)

  def testBytecodeCompilation(self):
    instructions = [
        (sock_diag.INET_DIAG_BC_S_GE,   1, 8, 0),                      # 0
        (sock_diag.INET_DIAG_BC_D_LE,   1, 7, 0xffff),                 # 8
        (sock_diag.INET_DIAG_BC_S_COND, 1, 2, ("::1", 128, -1)),       # 16
        (sock_diag.INET_DIAG_BC_JMP,    1, 3, None),                   # 44
        (sock_diag.INET_DIAG_BC_S_COND, 2, 4, ("127.0.0.1", 32, -1)),  # 48
        (sock_diag.INET_DIAG_BC_D_LE,   1, 3, 0x6665),  # not used     # 64
        (sock_diag.INET_DIAG_BC_NOP,    1, 1, None),                   # 72
                                                                       # 76 acc
                                                                       # 80 rej
    ]
    bytecode = self.sock_diag.PackBytecode(instructions)
    expected = (
        "0208500000000000"
        "050848000000ffff"
        "071c20000a800000ffffffff00000000000000000000000000000001"
        "01041c00"
        "0718200002200000ffffffff7f000001"
        "0508100000006566"
        "00040400"
    )
    self.assertMultiLineEqual(expected, bytecode.encode("hex"))
    self.assertEquals(76, len(bytecode))
    self.socketpairs = self._CreateLotsOfSockets()
    filteredsockets = self.sock_diag.DumpAllInetSockets(IPPROTO_TCP, bytecode)
    allsockets = self.sock_diag.DumpAllInetSockets(IPPROTO_TCP, NO_BYTECODE)
    self.assertItemsEqual(allsockets, filteredsockets)

    # Pick a few sockets in hash table order, and check that the bytecode we
    # compiled selects them properly.
    for socketpair in self.socketpairs.values()[:20]:
      for s in socketpair:
        diag_msg = self.sock_diag.FindSockDiagFromFd(s)
        instructions = [
            (sock_diag.INET_DIAG_BC_S_GE, 1, 5, diag_msg.id.sport),
            (sock_diag.INET_DIAG_BC_S_LE, 1, 4, diag_msg.id.sport),
            (sock_diag.INET_DIAG_BC_D_GE, 1, 3, diag_msg.id.dport),
            (sock_diag.INET_DIAG_BC_D_LE, 1, 2, diag_msg.id.dport),
        ]
        bytecode = self.sock_diag.PackBytecode(instructions)
        self.assertEquals(32, len(bytecode))
        sockets = self.sock_diag.DumpAllInetSockets(IPPROTO_TCP, bytecode)
        self.assertEquals(1, len(sockets))

        # TODO: why doesn't comparing the cstructs work?
        self.assertEquals(diag_msg.Pack(), sockets[0][0].Pack())

  def testCrossFamilyBytecode(self):
    """Checks for a cross-family bug in inet_diag_hostcond matching.

    Relevant kernel commits:
      android-3.4:
        f67caec inet_diag: avoid unsafe and nonsensical prefix matches in inet_diag_bc_run()
    """
    # TODO: this is only here because the test fails if there are any open
    # sockets other than the ones it creates itself. Make the bytecode more
    # specific and remove it.
    self.assertFalse(self.sock_diag.DumpAllInetSockets(IPPROTO_TCP, ""))

    pair4 = net_test.CreateSocketPair(AF_INET, SOCK_STREAM, "127.0.0.1")
    pair6 = net_test.CreateSocketPair(AF_INET6, SOCK_STREAM, "::1")

    bytecode4 = self.sock_diag.PackBytecode([
        (sock_diag.INET_DIAG_BC_S_COND, 1, 2, ("0.0.0.0", 0, -1))])
    bytecode6 = self.sock_diag.PackBytecode([
        (sock_diag.INET_DIAG_BC_S_COND, 1, 2, ("::", 0, -1))])

    # IPv4/v6 filters must never match IPv6/IPv4 sockets...
    v4sockets = self.sock_diag.DumpAllInetSockets(IPPROTO_TCP, bytecode4)
    self.assertTrue(v4sockets)
    self.assertTrue(all(d.family == AF_INET for d, _ in v4sockets))

    v6sockets = self.sock_diag.DumpAllInetSockets(IPPROTO_TCP, bytecode6)
    self.assertTrue(v6sockets)
    self.assertTrue(all(d.family == AF_INET6 for d, _ in v6sockets))

    # Except for mapped addresses, which match both IPv4 and IPv6.
    pair5 = net_test.CreateSocketPair(AF_INET6, SOCK_STREAM,
                                      "::ffff:127.0.0.1")
    diag_msgs = [self.sock_diag.FindSockDiagFromFd(s) for s in pair5]
    v4sockets = [d for d, _ in self.sock_diag.DumpAllInetSockets(IPPROTO_TCP,
                                                                 bytecode4)]
    v6sockets = [d for d, _ in self.sock_diag.DumpAllInetSockets(IPPROTO_TCP,
                                                                 bytecode6)]
    self.assertTrue(all(d in v4sockets for d in diag_msgs))
    self.assertTrue(all(d in v6sockets for d in diag_msgs))

  def testPortComparisonValidation(self):
    """Checks for a bug in validating port comparison bytecode.

    Relevant kernel commits:
      android-3.4:
        5e1f542 inet_diag: validate port comparison byte code to prevent unsafe reads
    """
    bytecode = sock_diag.InetDiagBcOp((sock_diag.INET_DIAG_BC_D_GE, 4, 8))
    self.assertRaisesErrno(
        EINVAL,
        self.sock_diag.DumpAllInetSockets, IPPROTO_TCP, bytecode.Pack())

  @unittest.skipUnless(HAVE_SOCK_DESTROY, "SOCK_DESTROY not supported")
  def testClosesSockets(self):
    self.socketpairs = self._CreateLotsOfSockets()
    for (addr, _, _), socketpair in self.socketpairs.iteritems():
      # Close one of the sockets.
      # This will send a RST that will close the other side as well.
      s = random.choice(socketpair)
      if random.randrange(0, 2) == 1:
        self.sock_diag.CloseSocketFromFd(s)
      else:
        diag_msg = self.sock_diag.FindSockDiagFromFd(s)
        family = AF_INET6 if ":" in addr else AF_INET

        # Get the cookie wrong and ensure that we get an error and the socket
        # is not closed.
        real_cookie = diag_msg.id.cookie
        diag_msg.id.cookie = os.urandom(len(real_cookie))
        req = self.sock_diag.DiagReqFromDiagMsg(diag_msg, IPPROTO_TCP)
        self.assertRaisesErrno(ENOENT, self.sock_diag.CloseSocket, req)
        self.assertSocketConnected(s)

        # Now close it with the correct cookie.
        req.id.cookie = real_cookie
        self.sock_diag.CloseSocket(req)

      # Check that both sockets in the pair are closed.
      self.assertSocketsClosed(socketpair)

  @unittest.skipUnless(HAVE_SOCK_DESTROY, "SOCK_DESTROY not supported")
  def testNonTcpSockets(self):
    s = socket(AF_INET6, SOCK_DGRAM, 0)
    s.connect(("::1", 53))
    diag_msg = self.sock_diag.FindSockDiagFromFd(s)
    self.assertRaisesErrno(EOPNOTSUPP, self.sock_diag.CloseSocketFromFd, s)

  def testNonSockDiagCommand(self):
    def DiagDump(code):
      sock_id = self.sock_diag._EmptyInetDiagSockId()
      req = sock_diag.InetDiagReqV2((AF_INET6, IPPROTO_TCP, 0, 0xffffffff,
                                     sock_id))
      self.sock_diag._Dump(code, req, sock_diag.InetDiagMsg, "")

    op = sock_diag.SOCK_DIAG_BY_FAMILY
    DiagDump(op)  # No errors? Good.
    self.assertRaisesErrno(EINVAL, DiagDump, op + 17)

  # TODO:
  # Test that killing unix sockets returns EOPNOTSUPP.


class SocketExceptionThread(threading.Thread):

  def __init__(self, sock, operation):
    self.exception = None
    super(SocketExceptionThread, self).__init__()
    self.daemon = True
    self.sock = sock
    self.operation = operation

  def run(self):
    try:
      self.operation(self.sock)
    except Exception, e:
      self.exception = e


# TODO: Take a tun fd as input, make this a utility class, and reuse at least
# in forwarding_test.
class TcpTest(SockDiagBaseTest):

  NOT_YET_ACCEPTED = -1

  def setUp(self):
    super(TcpTest, self).setUp()
    self.sock_diag = sock_diag.SockDiag()
    self.netid = random.choice(self.tuns.keys())

  def OpenListenSocket(self, version):
    self.port = packets.RandomPort()
    family = {4: AF_INET, 6: AF_INET6}[version]
    address = {4: "0.0.0.0", 6: "::"}[version]
    s = net_test.Socket(family, SOCK_STREAM, IPPROTO_TCP)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind((address, self.port))
    # We haven't configured inbound iptables marking, so bind explicitly.
    self.SelectInterface(s, self.netid, "mark")
    s.listen(100)
    return s

  def _ReceiveAndExpectResponse(self, netid, packet, reply, msg):
    pkt = super(TcpTest, self)._ReceiveAndExpectResponse(netid, packet,
                                                         reply, msg)
    self.last_packet = pkt
    return pkt

  def ReceivePacketOn(self, netid, packet):
    super(TcpTest, self).ReceivePacketOn(netid, packet)
    self.last_packet = packet

  def RstPacket(self):
    return packets.RST(self.version, self.myaddr, self.remoteaddr,
                       self.last_packet)

  def IncomingConnection(self, version, end_state, netid):
    if version == 5:
      mapped = True
      socket_version = 6
      version = 4
    else:
      socket_version = version
      mapped = False

    self.version = version
    self.s = self.OpenListenSocket(socket_version)
    self.end_state = end_state

    def MaybeMappedAddress(addr):
      return "::ffff:%s" % addr if mapped else addr

    remoteaddr = self.remoteaddr = MaybeMappedAddress(
        self.GetRemoteAddress(version))
    myaddr = self.myaddr = MaybeMappedAddress(
        self.MyAddress(version, netid))

    if end_state == sock_diag.TCP_LISTEN:
      return

    desc, syn = packets.SYN(self.port, version, remoteaddr, myaddr)
    synack_desc, synack = packets.SYNACK(version, myaddr, remoteaddr, syn)
    msg = "Received %s, expected to see reply %s" % (desc, synack_desc)
    reply = self._ReceiveAndExpectResponse(netid, syn, synack, msg)
    if end_state == sock_diag.TCP_SYN_RECV:
      return

    establishing_ack = packets.ACK(version, remoteaddr, myaddr, reply)[1]
    self.ReceivePacketOn(netid, establishing_ack)

    if end_state == self.NOT_YET_ACCEPTED:
      return

    self.accepted, _ = self.s.accept()
    net_test.DisableLinger(self.accepted)

    if end_state == sock_diag.TCP_ESTABLISHED:
      return

    desc, data = packets.ACK(version, myaddr, remoteaddr, establishing_ack,
                             payload=net_test.UDP_PAYLOAD)
    self.accepted.send(net_test.UDP_PAYLOAD)
    self.ExpectPacketOn(netid, msg + ": expecting %s" % desc, data)

    desc, fin = packets.FIN(version, remoteaddr, myaddr, data)
    fin = packets._GetIpLayer(version)(str(fin))
    ack_desc, ack = packets.ACK(version, myaddr, remoteaddr, fin)
    msg = "Received %s, expected to see reply %s" % (desc, ack_desc)

    # TODO: Why can't we use this?
    #   self._ReceiveAndExpectResponse(netid, fin, ack, msg)
    self.ReceivePacketOn(netid, fin)
    time.sleep(0.1)
    self.ExpectPacketOn(netid, msg + ": expecting %s" % ack_desc, ack)
    if end_state == sock_diag.TCP_CLOSE_WAIT:
      return

    raise ValueError("Invalid TCP state %d specified" % end_state)

  def CheckRstOnClose(self, sock, req, expect_reset, msg, do_close=True):
    """Closes the socket and checks whether a RST is sent or not."""
    if sock is not None:
      self.assertIsNone(req, "Must specify sock or req, not both")
      self.sock_diag.CloseSocketFromFd(sock)
      self.assertRaisesErrno(EINVAL, sock.accept)
    else:
      self.assertIsNone(sock, "Must specify sock or req, not both")
      self.sock_diag.CloseSocket(req)

    if expect_reset:
      desc, rst = self.RstPacket()
      msg = "%s: expecting %s: " % (msg, desc)
      self.ExpectPacketOn(self.netid, msg, rst)
    else:
      msg = "%s: " % msg
      self.ExpectNoPacketsOn(self.netid, msg)

    if sock is not None and do_close:
      sock.close()

  def CheckTcpReset(self, state, statename):
    for version in [4, 6]:
      msg = "Closing incoming IPv%d %s socket" % (version, statename)
      self.IncomingConnection(version, state, self.netid)
      self.CheckRstOnClose(self.s, None, False, msg)
      if state != sock_diag.TCP_LISTEN:
        msg = "Closing accepted IPv%d %s socket" % (version, statename)
        self.CheckRstOnClose(self.accepted, None, True, msg)

  @unittest.skipUnless(HAVE_SOCK_DESTROY, "SOCK_DESTROY not supported")
  def testTcpResets(self):
    """Checks that closing sockets in appropriate states sends a RST."""
    self.CheckTcpReset(sock_diag.TCP_LISTEN, "TCP_LISTEN")
    self.CheckTcpReset(sock_diag.TCP_ESTABLISHED, "TCP_ESTABLISHED")
    self.CheckTcpReset(sock_diag.TCP_CLOSE_WAIT, "TCP_CLOSE_WAIT")

  def FindChildSockets(self, s):
    """Finds the SYN_RECV child sockets of a given listening socket."""
    d = self.sock_diag.FindSockDiagFromFd(self.s)
    req = self.sock_diag.DiagReqFromDiagMsg(d, IPPROTO_TCP)
    req.states = 1 << sock_diag.TCP_SYN_RECV | 1 << sock_diag.TCP_ESTABLISHED
    req.id.cookie = "\x00" * 8
    children = self.sock_diag.Dump(req, NO_BYTECODE)
    return [self.sock_diag.DiagReqFromDiagMsg(d, IPPROTO_TCP)
            for d, _ in children]

  def CheckChildSocket(self, state, statename, parent_first):
    for version in [4, 6]:
      self.IncomingConnection(version, state, self.netid)

      d = self.sock_diag.FindSockDiagFromFd(self.s)
      parent = self.sock_diag.DiagReqFromDiagMsg(d, IPPROTO_TCP)
      children = self.FindChildSockets(self.s)
      self.assertEquals(1, len(children))

      is_established = (state == self.NOT_YET_ACCEPTED)

      # The new TCP listener code in 4.4 makes SYN_RECV sockets live in the
      # regular TCP hash tables, and inet_diag_find_one_icsk can find them.
      # Before 4.4, we can see those sockets in dumps, but we can't fetch
      # or close them.
      can_close_children = is_established or net_test.LINUX_VERSION >= (4, 4)

      for child in children:
        if can_close_children:
          self.sock_diag.GetSockDiag(child)  # No errors? Good, child found.
        else:
          self.assertRaisesErrno(ENOENT, self.sock_diag.GetSockDiag, child)

      def CloseParent(expect_reset):
        msg = "Closing parent IPv%d %s socket %s child" % (
            version, statename, "before" if parent_first else "after")
        self.CheckRstOnClose(self.s, None, expect_reset, msg)
        self.assertRaisesErrno(ENOENT, self.sock_diag.GetSockDiag, parent)

      def CheckChildrenClosed():
        for child in children:
          self.assertRaisesErrno(ENOENT, self.sock_diag.GetSockDiag, child)

      def CloseChildren():
        for child in children:
          msg = "Closing child IPv%d %s socket %s parent" % (
              version, statename, "after" if parent_first else "before")
          self.sock_diag.GetSockDiag(child)
          self.CheckRstOnClose(None, child, is_established, msg)
          self.assertRaisesErrno(ENOENT, self.sock_diag.GetSockDiag, child)
        CheckChildrenClosed()

      if parent_first:
        # Closing the parent will close child sockets, which will send a RST,
        # iff they are already established.
        CloseParent(is_established)
        if is_established:
          CheckChildrenClosed()
        elif can_close_children:
          CloseChildren()
          CheckChildrenClosed()
        self.s.close()
      else:
        if can_close_children:
          CloseChildren()
        CloseParent(False)
        self.s.close()

  @unittest.skipUnless(HAVE_SOCK_DESTROY, "SOCK_DESTROY not supported")
  def testChildSockets(self):
    self.CheckChildSocket(sock_diag.TCP_SYN_RECV, "TCP_SYN_RECV", False)
    self.CheckChildSocket(sock_diag.TCP_SYN_RECV, "TCP_SYN_RECV", True)
    self.CheckChildSocket(self.NOT_YET_ACCEPTED, "not yet accepted", False)
    self.CheckChildSocket(self.NOT_YET_ACCEPTED, "not yet accepted", True)

  def CloseDuringBlockingCall(self, sock, call, expected_errno):
    thread = SocketExceptionThread(sock, call)
    thread.start()
    time.sleep(0.1)
    self.sock_diag.CloseSocketFromFd(sock)
    thread.join(1)
    self.assertFalse(thread.is_alive())
    self.assertIsNotNone(thread.exception)
    self.assertTrue(isinstance(thread.exception, IOError),
                    "Expected IOError, got %s" % thread.exception)
    self.assertEqual(expected_errno, thread.exception.errno)
    self.assertSocketClosed(sock)

  @unittest.skipUnless(HAVE_SOCK_DESTROY, "SOCK_DESTROY not supported")
  def testAcceptInterrupted(self):
    """Tests that accept() is interrupted by SOCK_DESTROY."""
    for version in [4, 5, 6]:
      self.IncomingConnection(version, sock_diag.TCP_LISTEN, self.netid)
      self.CloseDuringBlockingCall(self.s, lambda sock: sock.accept(), EINVAL)
      self.assertRaisesErrno(ECONNABORTED, self.s.send, "foo")
      self.assertRaisesErrno(EINVAL, self.s.accept)

  @unittest.skipUnless(HAVE_SOCK_DESTROY, "SOCK_DESTROY not supported")
  def testReadInterrupted(self):
    """Tests that read() is interrupted by SOCK_DESTROY."""
    for version in [4, 5, 6]:
      self.IncomingConnection(version, sock_diag.TCP_ESTABLISHED, self.netid)
      self.CloseDuringBlockingCall(self.accepted, lambda sock: sock.recv(4096),
                                   ECONNABORTED)
      self.assertRaisesErrno(EPIPE, self.accepted.send, "foo")

  @unittest.skipUnless(HAVE_SOCK_DESTROY, "SOCK_DESTROY not supported")
  def testConnectInterrupted(self):
    """Tests that connect() is interrupted by SOCK_DESTROY."""
    for version in [4, 5, 6]:
      family = {4: AF_INET, 5: AF_INET6, 6: AF_INET6}[version]
      s = net_test.Socket(family, SOCK_STREAM, IPPROTO_TCP)
      self.SelectInterface(s, self.netid, "mark")
      if version == 5:
        remoteaddr = "::ffff:" + self.GetRemoteAddress(4)
        version = 4
      else:
        remoteaddr = self.GetRemoteAddress(version)
      s.bind(("", 0))
      _, sport = s.getsockname()[:2]
      self.CloseDuringBlockingCall(
          s, lambda sock: sock.connect((remoteaddr, 53)), ECONNABORTED)
      desc, syn = packets.SYN(53, version, self.MyAddress(version, self.netid),
                              remoteaddr, sport=sport, seq=None)
      self.ExpectPacketOn(self.netid, desc, syn)
      msg = "SOCK_DESTROY of socket in connect, expected no RST"
      self.ExpectNoPacketsOn(self.netid, msg)

  def testIpv4MappedSynRecvSocket(self):
    """Tests for the absence of a bug with AF_INET6 TCP SYN-RECV sockets.

    Relevant kernel commits:
         android-3.4:
           457a04b inet_diag: fix oops for IPv4 AF_INET6 TCP SYN-RECV state
    """
    self.IncomingConnection(5, sock_diag.TCP_SYN_RECV, self.netid)
    sock_id = self.sock_diag._EmptyInetDiagSockId()
    sock_id.sport = self.port
    states = 1 << sock_diag.TCP_SYN_RECV
    req = sock_diag.InetDiagReqV2((AF_INET6, IPPROTO_TCP, 0, states, sock_id))
    children = self.sock_diag.Dump(req, NO_BYTECODE)

    self.assertTrue(children)
    for child, unused_args in children:
      self.assertEqual(sock_diag.TCP_SYN_RECV, child.state)
      self.assertEqual(self.sock_diag.PaddedAddress(self.remoteaddr),
                       child.id.dst)
      self.assertEqual(self.sock_diag.PaddedAddress(self.myaddr),
                       child.id.src)


if __name__ == "__main__":
  unittest.main()
