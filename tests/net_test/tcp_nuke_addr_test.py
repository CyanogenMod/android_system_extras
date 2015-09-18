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
import fcntl
import os
import socket
import struct
import threading
import time
import unittest


IPV4_LOOPBACK_ADDR = '127.0.0.1'
IPV6_LOOPBACK_ADDR = '::1'

SIOCKILLADDR = 0x8939

DEFAULT_TCP_PORT = 8001
DEFAULT_BUFFER_SIZE = 20
DEFAULT_TEST_MESSAGE = "TCP NUKE ADDR TEST"


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


def ExchangeMessage(addr_family, ip_addr, tcp_port,
                    message=DEFAULT_TEST_MESSAGE):
  """Creates a listening socket, accepts a connection and sends data to it.

  Args:
    addr_family: The address family (e.g. AF_INET6).
    ip_addr: The IP address (IPv4 or IPv6 depending on the addr_family).
    tcp_port: The TCP port to listen on.
    message: The message to send on the socket.
  """
  test_addr = (ip_addr, tcp_port)
  with contextlib.closing(
      socket.socket(addr_family, socket.SOCK_STREAM)) as listening_socket:
    listening_socket.bind(test_addr)
    listening_socket.listen(1)
    with RunInBackground(threading.Thread(target=TcpAcceptAndReceive,
                                          args=(listening_socket,))):
      with contextlib.closing(
          socket.socket(addr_family, socket.SOCK_STREAM)) as client_socket:
        client_socket.connect(test_addr)
        client_socket.send(message)


def KillAddrIoctl(addr_family):
  """Calls the SIOCKILLADDR on IPv6 address family.

  Args:
    addr_family: The address family (e.g. AF_INET6).

  Raises:
    ValueError: If the address family is invalid for the ioctl.
  """
  if addr_family == socket.AF_INET6:
    ifreq = struct.pack('BBBBBBBBBBBBBBBBIi',
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                        128, 1)
  elif addr_family == socket.AF_INET:
    raise NotImplementedError('Support for IPv4 not implemented yet.')
  else:
    raise ValueError('Address family %r not supported.' % addr_family)
  datagram_socket = socket.socket(addr_family, socket.SOCK_DGRAM)
  fcntl.ioctl(datagram_socket.fileno(), SIOCKILLADDR, ifreq)
  datagram_socket.close()


class TcpNukeAddrTest(unittest.TestCase):

  def testIPv6KillAddr(self):
    """Tests that SIOCKILLADDR works as expected.

    Relevant kernel commits:
      https://www.codeaurora.org/cgit/quic/la/kernel/msm-3.18/commit/net/ipv4/tcp.c?h=aosp/android-3.10&id=1dcd3a1fa2fe78251cc91700eb1d384ab02e2dd6
    """
    ExchangeMessage(socket.AF_INET6, IPV6_LOOPBACK_ADDR, DEFAULT_TCP_PORT)
    KillAddrIoctl(socket.AF_INET6)
    # Test passes if kernel does not crash.


if __name__ == "__main__":
  unittest.main()
