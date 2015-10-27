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

import contextlib
import errno
import fcntl
import resource
import os
from socket import *  # pylint: disable=wildcard-import
import struct
import threading
import time
import unittest

import csocket
import cstruct
import net_test

IPV4_LOOPBACK_ADDR = "127.0.0.1"
IPV6_LOOPBACK_ADDR = "::1"
LOOPBACK_DEV = "lo"
LOOPBACK_IFINDEX = 1

SIOCKILLADDR = 0x8939

DEFAULT_TCP_PORT = 8001
DEFAULT_BUFFER_SIZE = 20
DEFAULT_TEST_MESSAGE = "TCP NUKE ADDR TEST"
DEFAULT_TEST_RUNS = 100
HASH_TEST_RUNS = 4000
HASH_TEST_NOFILE = 16384


Ifreq = cstruct.Struct("Ifreq", "=16s16s", "name data")
In6Ifreq = cstruct.Struct("In6Ifreq", "=16sIi", "addr prefixlen ifindex")

@contextlib.contextmanager
def RunInBackground(thread):
  """Starts a thread and waits until it joins.

  Args:
    thread: A not yet started threading.Thread object.
  """
  try:
    thread.start()
    yield thread
  finally:
    thread.join()


def TcpAcceptAndReceive(listening_sock, buffer_size=DEFAULT_BUFFER_SIZE):
  """Accepts a single connection and blocks receiving data from it.

  Args:
    listening_socket: A socket in LISTEN state.
    buffer_size: Size of buffer where to read a message.
  """
  connection, _ = listening_sock.accept()
  with contextlib.closing(connection):
    _ = connection.recv(buffer_size)


def ExchangeMessage(addr_family, ip_addr):
  """Creates a listening socket, accepts a connection and sends data to it.

  Args:
    addr_family: The address family (e.g. AF_INET6).
    ip_addr: The IP address (IPv4 or IPv6 depending on the addr_family).
    tcp_port: The TCP port to listen on.
  """
  # Bind to a random port and connect to it.
  test_addr = (ip_addr, 0)
  with contextlib.closing(
      socket(addr_family, SOCK_STREAM)) as listening_socket:
    listening_socket.bind(test_addr)
    test_addr = listening_socket.getsockname()
    listening_socket.listen(1)
    with RunInBackground(threading.Thread(target=TcpAcceptAndReceive,
                                          args=(listening_socket,))):
      with contextlib.closing(
          socket(addr_family, SOCK_STREAM)) as client_socket:
        client_socket.connect(test_addr)
        client_socket.send(DEFAULT_TEST_MESSAGE)


def KillAddrIoctl(addr_family):
  """Calls the SIOCKILLADDR on IPv6 address family.

  Args:
    addr_family: The address family (e.g. AF_INET6).

  Raises:
    ValueError: If the address family is invalid for the ioctl.
  """
  if addr_family == AF_INET6:
    addr = inet_pton(AF_INET6, IPV6_LOOPBACK_ADDR)
    ifreq = In6Ifreq((addr, 128, LOOPBACK_IFINDEX)).Pack()
  elif addr_family == AF_INET:
    addr = inet_pton(AF_INET, IPV4_LOOPBACK_ADDR)
    sockaddr = csocket.SockaddrIn((AF_INET, 0, addr)).Pack()
    ifreq = Ifreq((LOOPBACK_DEV, sockaddr)).Pack()
  else:
    raise ValueError('Address family %r not supported.' % addr_family)
  datagram_socket = socket(addr_family, SOCK_DGRAM)
  fcntl.ioctl(datagram_socket.fileno(), SIOCKILLADDR, ifreq)
  datagram_socket.close()


class ExceptionalReadThread(threading.Thread):

  def __init__(self, sock):
    self.sock = sock
    self.exception = None
    super(ExceptionalReadThread, self).__init__()
    self.daemon = True

  def run(self):
    try:
      read = self.sock.recv(4096)
    except Exception, e:
      self.exception = e


def CreateSocketPair(family, addr):
  clientsock = socket(family, SOCK_STREAM, 0)
  listensock = socket(family, SOCK_STREAM, 0)
  listensock.bind((addr, 0))
  addr = listensock.getsockname()
  listensock.listen(1)
  clientsock.connect(addr)
  acceptedsock, _ = listensock.accept()
  return clientsock, acceptedsock


class TcpNukeAddrTest(net_test.NetworkTest):

  def testTimewaitSockets(self):
    """Tests that SIOCKILLADDR works as expected.

    Relevant kernel commits:
      https://www.codeaurora.org/cgit/quic/la/kernel/msm-3.18/commit/net/ipv4/tcp.c?h=aosp/android-3.10&id=1dcd3a1fa2fe78251cc91700eb1d384ab02e2dd6
    """
    for i in xrange(DEFAULT_TEST_RUNS):
      ExchangeMessage(AF_INET6, IPV6_LOOPBACK_ADDR)
      KillAddrIoctl(AF_INET6)
      ExchangeMessage(AF_INET, IPV4_LOOPBACK_ADDR)
      KillAddrIoctl(AF_INET)
      # Test passes if kernel does not crash.

  def testClosesSockets(self):
    """Tests that SIOCKILLADDR closes IPv6 sockets."""

    threadpairs = []

    for i in xrange(DEFAULT_TEST_RUNS):
      clientsock, acceptedsock = CreateSocketPair(AF_INET6, "::1")
      clientthread = ExceptionalReadThread(clientsock)
      clientthread.start()
      serverthread = ExceptionalReadThread(acceptedsock)
      serverthread.start()
      threadpairs.append((clientthread, serverthread))

    KillAddrIoctl(AF_INET6)

    def CheckThreadException(thread):
      thread.join(100)
      self.assertFalse(thread.is_alive())
      self.assertIsNotNone(thread.exception)
      self.assertTrue(isinstance(thread.exception, IOError))
      self.assertEquals(errno.ETIMEDOUT, thread.exception.errno)
      self.assertRaisesErrno(errno.ENOTCONN, thread.sock.getpeername)
      self.assertRaisesErrno(errno.EISCONN, thread.sock.connect, ("::1", 53))
      self.assertRaisesErrno(errno.EPIPE, thread.sock.send, "foo")

    for clientthread, serverthread in threadpairs:
      CheckThreadException(clientthread)
      CheckThreadException(serverthread)


class TcpNukeAddrHashTest(net_test.NetworkTest):

  def setUp(self):
    self.nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (HASH_TEST_NOFILE,
                                                HASH_TEST_NOFILE))

  def tearDown(self):
    resource.setrlimit(resource.RLIMIT_NOFILE, self.nofile)

  def testClosesAllSockets(self):
    socketpairs = []
    for i in xrange(HASH_TEST_RUNS):
      socketpairs.append(CreateSocketPair(AF_INET, IPV4_LOOPBACK_ADDR))
      socketpairs.append(CreateSocketPair(AF_INET6, IPV6_LOOPBACK_ADDR))

    KillAddrIoctl(AF_INET)
    KillAddrIoctl(AF_INET6)

    for socketpair in socketpairs:
      for sock in socketpair:
        self.assertRaisesErrno(errno.ENOTCONN, sock.getpeername)


if __name__ == "__main__":
  unittest.main()
