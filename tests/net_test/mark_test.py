#!/usr/bin/python

import errno
import fcntl
import os
import posix
import random
import re
from socket import *  # pylint: disable=wildcard-import
import struct
import time
import unittest

from scapy import all as scapy

import iproute
import net_test

DEBUG = False

IFF_TUN = 1
IFF_TAP = 2
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

AUTOCONF_TABLE_SYSCTL = "/proc/sys/net/ipv6/route/autoconf_table_offset"

PING_IDENT = 0xff19
PING_PAYLOAD = "foobarbaz"
PING_SEQ = 3
PING_TOS = 0x83

TCP_SYN = 2
TCP_RST = 4
TCP_ACK = 16

TCP_SEQ = 1692871236
TCP_WINDOW = 14400

UDP_PAYLOAD = "hello"


class ConfigurationError(AssertionError):
  pass


class UnexpectedPacketError(AssertionError):
  pass


class Packets(object):

  @staticmethod
  def RandomPort():
    return random.randint(1025, 65535)

  @staticmethod
  def _GetIpLayer(version):
    return {4: scapy.IP, 6: scapy.IPv6}[version]

  @staticmethod
  def _SetPacketTos(packet, tos):
    if isinstance(packet, scapy.IPv6):
      packet.tc = tos
    elif isinstance(packet, scapy.IP):
      packet.tos = tos
    else:
      raise ValueError("Can't find ToS Field")

  @classmethod
  def UDP(cls, version, srcaddr, dstaddr, sport=0):
    ip = cls._GetIpLayer(version)
    # Can't just use "if sport" because None has meaning (it means unspecified).
    if sport == 0:
      sport = cls.RandomPort()
    return ("UDPv%d packet" % version,
            ip(src=srcaddr, dst=dstaddr) /
            scapy.UDP(sport=sport, dport=53) / UDP_PAYLOAD)

  @classmethod
  def SYN(cls, dport, version, srcaddr, dstaddr, sport=0, seq=TCP_SEQ):
    ip = cls._GetIpLayer(version)
    if sport == 0:
      sport = cls.RandomPort()
    return ("TCP SYN",
            ip(src=srcaddr, dst=dstaddr) /
            scapy.TCP(sport=sport, dport=dport,
                      seq=seq, ack=0,
                      flags=TCP_SYN, window=TCP_WINDOW))

  @classmethod
  def RST(cls, version, srcaddr, dstaddr, packet):
    ip = cls._GetIpLayer(version)
    original = packet.getlayer("TCP")
    return ("TCP RST",
            ip(src=srcaddr, dst=dstaddr) /
            scapy.TCP(sport=original.dport, dport=original.sport,
                      ack=original.seq + 1, seq=None,
                      flags=TCP_RST | TCP_ACK, window=TCP_WINDOW))

  @classmethod
  def SYNACK(cls, version, srcaddr, dstaddr, packet):
    ip = cls._GetIpLayer(version)
    original = packet.getlayer("TCP")
    return ("TCP SYN+ACK",
            ip(src=srcaddr, dst=dstaddr) /
            scapy.TCP(sport=original.dport, dport=original.sport,
                      ack=original.seq + 1, seq=None,
                      flags=TCP_SYN | TCP_ACK, window=None))

  @classmethod
  def ACK(cls, version, srcaddr, dstaddr, packet):
    ip = cls._GetIpLayer(version)
    original = packet.getlayer("TCP")
    was_syn = (original.flags & TCP_SYN) != 0
    return ("TCP ACK",
            ip(src=srcaddr, dst=dstaddr) /
            scapy.TCP(sport=original.dport, dport=original.sport,
                      ack=original.seq + was_syn, seq=original.ack,
                      flags=TCP_ACK, window=TCP_WINDOW))

  @classmethod
  def ICMPPortUnreachable(cls, version, srcaddr, dstaddr, packet):
    if version == 4:
      # Linux hardcodes the ToS on ICMP errors to 0xc0 or greater because of
      # RFC 1812 4.3.2.5 (!).
      return ("ICMPv4 port unreachable",
              scapy.IP(src=srcaddr, dst=dstaddr, proto=1, tos=0xc0) /
              scapy.ICMPerror(type=3, code=3) / packet)
    else:
      return ("ICMPv6 port unreachable",
              scapy.IPv6(src=srcaddr, dst=dstaddr) /
              scapy.ICMPv6DestUnreach(code=4) / packet)

  @classmethod
  def ICMPEcho(cls, version, srcaddr, dstaddr):
    ip = cls._GetIpLayer(version)
    icmp = {4: scapy.ICMP, 6: scapy.ICMPv6EchoRequest}[version]
    packet = (ip(src=srcaddr, dst=dstaddr) /
              icmp(id=PING_IDENT, seq=PING_SEQ) / PING_PAYLOAD)
    cls._SetPacketTos(packet, PING_TOS)
    return ("ICMPv%d echo" % version, packet)

  @classmethod
  def ICMPReply(cls, version, srcaddr, dstaddr, packet):
    ip = cls._GetIpLayer(version)
    # Scapy doesn't provide an ICMP echo reply constructor.
    icmpv4_reply = lambda **kwargs: scapy.ICMP(type=0, **kwargs)
    icmp = {4: icmpv4_reply, 6: scapy.ICMPv6EchoReply}[version]
    packet = (ip(src=srcaddr, dst=dstaddr) /
              icmp(id=PING_IDENT, seq=PING_SEQ) / PING_PAYLOAD)
    cls._SetPacketTos(packet, PING_TOS)
    return ("ICMPv%d echo" % version, packet)


class MarkTest(net_test.NetworkTest):

  # Must be between 1 and 256, since we put them in MAC addresses and IIDs.
  NETIDS = [100, 150, 200, 250]

  @staticmethod
  def _RouterMacAddress(netid):
    return "02:00:00:00:%02x:00" % netid

  @staticmethod
  def _MyMacAddress(netid):
    return "02:00:00:00:%02x:01" % netid

  @staticmethod
  def _RouterAddress(netid, version):
    if version == 6:
      return "fe80::%02x00" % netid
    elif version == 4:
      return "10.0.%d.1" % netid
    else:
      raise ValueError("Don't support IPv%s" % version)

  @classmethod
  def _MyIPv4Address(cls, netid):
    return "10.0.%d.2" % netid

  @classmethod
  def _MyIPv6Address(cls, netid):
    return net_test.GetLinkAddress(cls._GetInterfaceName(netid), False)

  @classmethod
  def _MyAddress(cls, version, netid):
    return {4: cls._MyIPv4Address(netid),
            6: cls._MyIPv6Address(netid)}[version]

  @classmethod
  def _CreateTunInterface(cls, netid):
    iface = cls._GetInterfaceName(netid)
    f = open("/dev/net/tun", "r+b")
    ifr = struct.pack("16sH", iface, IFF_TAP | IFF_NO_PI)
    ifr += "\x00" * (40 - len(ifr))
    fcntl.ioctl(f, TUNSETIFF, ifr)
    # Give ourselves a predictable MAC address.
    net_test.SetInterfaceHWAddr(iface, cls._MyMacAddress(netid))
    # Disable DAD so we don't have to wait for it.
    open("/proc/sys/net/ipv6/conf/%s/dad_transmits" % iface, "w").write("0")
    net_test.SetInterfaceUp(iface)
    net_test.SetNonBlocking(f)
    return f

  @staticmethod
  def _GetInterfaceName(netid):
    return "nettest%d" % netid

  @classmethod
  def _SendRA(cls, netid):
    validity = 300                 # seconds
    validity_ms = validity * 1000  # milliseconds
    macaddr = cls._RouterMacAddress(netid)
    lladdr = cls._RouterAddress(netid, 6)
    ra = (scapy.Ether(src=macaddr, dst="33:33:00:00:00:01") /
          scapy.IPv6(src=lladdr, hlim=255) /
          scapy.ICMPv6ND_RA(retranstimer=validity_ms,
                            routerlifetime=validity) /
          scapy.ICMPv6NDOptSrcLLAddr(lladdr=macaddr) /
          scapy.ICMPv6NDOptPrefixInfo(prefix="2001:db8:%d::" % netid,
                                      prefixlen=64,
                                      L=1, A=1,
                                      validlifetime=validity,
                                      preferredlifetime=validity))
    posix.write(cls.tuns[netid].fileno(), str(ra))

  COMMANDS = [
      "/sbin/%(iptables)s %(append_delete)s INPUT -t mangle -i %(iface)s"
      " -j MARK --set-mark %(netid)d",
  ]
  ROUTE_COMMANDS = [
      "ip -%(version)d route %(add_del)s table %(table)s"
      " default dev %(iface)s via %(router)s",
  ]
  IPV4_COMMANDS = [
      "ip -4 nei %(add_del)s %(router)s dev %(iface)s"
      " lladdr %(macaddr)s nud permanent",
      "ip -4 addr %(add_del)s 10.0.%(netid)d.2/24 dev %(iface)s",
  ]

  @classmethod
  def _RunSetupCommands(cls, netid, is_add):
    iface = cls._GetInterfaceName(netid)
    for version, iptables in zip([4, 6], ["iptables", "ip6tables"]):

      table = cls._TableForNetid(netid)
      cls.iproute.FwmarkRule(version, is_add, netid, table)

      if version == 6:
        cmds = cls.COMMANDS
        if cls.AUTOCONF_TABLE_OFFSET < 0:
          # Set up routing manually.
          # Don't do cmds += cls.ROUTE_COMMANDS as this modifies cls.COMMANDS.
          cmds = cls.COMMANDS + cls.ROUTE_COMMANDS

      if version == 4:
        # Deleting addresses also causes routes to be deleted, so watch the
        # order or the test will output lots of ENOENT errors.
        if is_add:
          cmds = cls.COMMANDS + cls.IPV4_COMMANDS + cls.ROUTE_COMMANDS
        else:
          cmds = cls.COMMANDS + cls.ROUTE_COMMANDS + cls.IPV4_COMMANDS

      cmds = str("\n".join(cmds) % {
          "add_del": "add" if is_add else "del",
          "append_delete": "-A" if is_add else "-D",
          "iface": iface,
          "iptables": iptables,
          "ipv4addr": cls._MyIPv4Address(netid),
          "macaddr": cls._RouterMacAddress(netid),
          "netid": netid,
          "router": cls._RouterAddress(netid, version),
          "table": table,
          "version": version,
      }).split("\n")
      for cmd in cmds:
        cmd = cmd.split(" ")
        if DEBUG: print " ".join(cmd)
        ret = os.spawnvp(os.P_WAIT, cmd[0], cmd)
        if ret:
          raise ConfigurationError("Setup command failed: %s" % " ".join(cmd))

  @classmethod
  def _SetAutoconfTableSysctl(cls, offset):
    try:
      open(AUTOCONF_TABLE_SYSCTL, "w").write(str(offset))
      cls.AUTOCONF_TABLE_OFFSET = offset
    except IOError:
      cls.AUTOCONF_TABLE_OFFSET = -1

  @classmethod
  def _TableForNetid(cls, netid):
    if cls.AUTOCONF_TABLE_OFFSET >= 0:
      return cls.ifindices[netid] + cls.AUTOCONF_TABLE_OFFSET
    else:
      return netid

  @classmethod
  def _ICMPRatelimitFilename(cls, version):
    return "/proc/sys/net/" + {4: "ipv4/icmp_ratelimit",
                               6: "ipv6/icmp/ratelimit"}[version]

  @classmethod
  def _GetICMPRatelimit(cls, version):
    return int(open(cls._ICMPRatelimitFilename(version), "r").read().strip())

  @classmethod
  def _SetICMPRatelimit(cls, version, limit):
    return open(cls._ICMPRatelimitFilename(version), "w").write("%d" % limit)

  @classmethod
  def setUpClass(cls):
    # This is per-class setup instead of per-testcase setup because shelling out
    # to ip and iptables is slow, and because routing configuration doesn't
    # change during the test.
    cls.iproute = iproute.IPRoute()
    cls.tuns = {}
    cls.ifindices = {}
    cls._SetAutoconfTableSysctl(1000)

    # Disable ICMP rate limits.
    cls.ratelimits = {}
    for version in [4, 6]:
      cls.ratelimits[version] = cls._GetICMPRatelimit(version)
      cls._SetICMPRatelimit(version, 0)

    for netid in cls.NETIDS:
      cls.tuns[netid] = cls._CreateTunInterface(netid)

      iface = cls._GetInterfaceName(netid)
      cls.ifindices[netid] = net_test.GetInterfaceIndex(iface)

      cls._SendRA(netid)
      cls._RunSetupCommands(netid, True)

    # Open a port so we can observe SYN+ACKs. Since it's a dual-stack socket it
    # will accept both IPv4 and IPv6 connections. We do this here instead of in
    # each test so we can use the same socket every time. That way, if a kernel
    # bug causes incoming packets to mark the listening socket instead of the
    # accepted socket, the test will fail as soon as the next address/interface
    # combination is tried.
    cls.listenport = 1234
    cls.listensocket = net_test.IPv6TCPSocket()
    cls.listensocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    cls.listensocket.bind(("::", cls.listenport))
    cls.listensocket.listen(100)

    # Give time for unknown things to settle down.
    time.sleep(0.5)
    # Uncomment to look around at interface and rule configuration while
    # running in the background. (Once the test finishes running, all the
    # interfaces and rules are gone.)
    # time.sleep(30)

  @classmethod
  def tearDownClass(cls):
    for netid in cls.tuns:
      cls._RunSetupCommands(netid, False)
      cls.tuns[netid].close()
    cls._SetAutoconfTableSysctl(-1)
    for version in [4, 6]:
      cls._SetICMPRatelimit(version, cls.ratelimits[version])

  def assertPacketMatches(self, expected, actual):
    # Remove the Ethernet header from the incoming packet.
    actual = scapy.Ether(actual).payload

    # Blank out IPv4 fields that we can't predict, like ID and the DF bit.
    actualip = actual.getlayer("IP")
    expectedip = expected.getlayer("IP")
    if actualip and expectedip:
      actualip.id = expectedip.id
      actualip.flags &= 5
      actualip.chksum = None  # Change the header, recalculate the checksum.

    # Blank out UDP fields that we can't predict (e.g., the source port for
    # kernel-originated packets).
    actualudp = actual.getlayer("UDP")
    expectedudp = expected.getlayer("UDP")
    if actualudp and expectedudp:
      if expectedudp.sport is None:
        actualudp.sport = None
        actualudp.chksum = None

    # Since the TCP code below messes with options, recalculate the length.
    if actualip:
      actualip.len = None
    actualipv6 = actual.getlayer("IPv6")
    if actualipv6:
      actualipv6.plen = None

    # Blank out TCP fields that we can't predict.
    actualtcp = actual.getlayer("TCP")
    expectedtcp = expected.getlayer("TCP")
    if actualtcp and expectedtcp:
      actualtcp.dataofs = expectedtcp.dataofs
      actualtcp.options = expectedtcp.options
      actualtcp.window = expectedtcp.window
      if expectedtcp.sport is None:
        actualtcp.sport = None
      if expectedtcp.seq is None:
        actualtcp.seq = None
      if expectedtcp.ack is None:
        actualtcp.ack = None
      actualtcp.chksum = None

    # Serialize the packet so:
    # - Expected packet fields that are only set when a packet is serialized
    #   (e.g., the checksum) are filled in.
    # - The packet is vaguely human-readable. Scapy has sophisticated packet
    #   dissection capabilities, but unfortunately they can only be used to
    #   print the packet, not to return its dissection as as string.
    self.assertMultiLineEqual(str(expected).encode("hex"),
                              str(actual).encode("hex"))

  def PacketMatches(self, expected, actual):
    try:
      self.assertPacketMatches(expected, actual)
      return True
    except AssertionError:
      return False

  def ReadAllPacketsOn(self, netid):
    packets = []
    while True:
      try:
        packets.append(posix.read(self.tuns[netid].fileno(), 4096))
      except OSError, e:
        # EAGAIN means there are no more packets waiting.
        if re.match(e.message, os.strerror(errno.EAGAIN)):
          break
        # Anything else is unexpected.
        else:
          raise e
    return packets

  def ExpectPacketOn(self, netid, msg, expected):
    packets = self.ReadAllPacketsOn(netid)
    self.assertTrue(packets, msg + ": received no packets")

    # If we receive a packet that matches what we expected, return it.
    for packet in packets:
      if self.PacketMatches(expected, packet):
        return scapy.Ether(packet).payload

    # None of the packets matched. Call assertPacketMatches to output a diff
    # between the expected packet and the last packet we received. In theory,
    # we'd output a diff to the packet that's the best match for what we
    # expected, but this is good enough for now.
    try:
      self.assertPacketMatches(expected, packets[-1])
    except Exception, e:
      raise UnexpectedPacketError(
          "%s: diff with last packet:\n%s" % (msg, e.message))

  def ReceivePacketOn(self, netid, ip_packet):
    routermac = self._RouterMacAddress(netid)
    mymac = self._MyMacAddress(netid)
    packet = scapy.Ether(src=routermac, dst=mymac) / ip_packet
    posix.write(self.tuns[netid].fileno(), str(packet))

  def ClearTunQueues(self):
    # Keep reading packets on all netids until we get no packets on any of them.
    waiting = None
    while waiting != 0:
      waiting = sum(len(self.ReadAllPacketsOn(netid)) for netid in self.NETIDS)

  def setUp(self):
    self.ClearTunQueues()

  @staticmethod
  def _GetRemoteAddress(version):
    return {4: net_test.IPV4_ADDR, 6: net_test.IPV6_ADDR}[version]

  def SetSocketMark(self, s, netid):
    s.setsockopt(SOL_SOCKET, net_test.SO_MARK, netid)

  def GetSocketMark(self, s):
    return s.getsockopt(SOL_SOCKET, net_test.SO_MARK)

  def GetProtocolFamily(self, version):
    return {4: AF_INET, 6: AF_INET6}[version]

  def testOutgoingPackets(self):
    """Checks that socket marking selects the right outgoing interface."""

    def CheckPingPacket(version, netid, dstaddr, packet):
      s = net_test.PingSocket(self.GetProtocolFamily(version))
      myaddr = self._MyAddress(version, netid)
      s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
      s.bind((myaddr, PING_IDENT))
      self.SetSocketMark(s, netid)
      net_test.SetSocketTos(s, PING_TOS)

      desc, expected = Packets.ICMPEcho(version, myaddr, dstaddr)

      self.ClearTunQueues()
      s.sendto(packet + PING_PAYLOAD, (dstaddr, 19321))
      msg = "IPv%d ping: expected %s on %s" % (
          version, desc, self._GetInterfaceName(netid))
      self.ExpectPacketOn(netid, msg, expected)

    for netid in self.tuns:
      CheckPingPacket(4, netid, net_test.IPV4_ADDR, net_test.IPV4_PING)
      CheckPingPacket(6, netid, net_test.IPV6_ADDR, net_test.IPV6_PING)

    def CheckTCPSYNPacket(version, netid, dstaddr):
      s = net_test.TCPSocket(self.GetProtocolFamily(version))
      self.SetSocketMark(s, netid)
      if version == 6 and dstaddr.startswith("::ffff"):
        version = 4
      myaddr = self._MyAddress(version, netid)
      desc, expected = Packets.SYN(53, version, myaddr, dstaddr,
                                   sport=None, seq=None)

      self.ClearTunQueues()
      # Non-blocking TCP connects always return EINPROGRESS.
      self.assertRaisesErrno(errno.EINPROGRESS, s.connect, (dstaddr, 53))
      msg = "IPv%s TCP connect: expected %s on %s" % (
          version, desc, self._GetInterfaceName(netid))
      self.ExpectPacketOn(netid, msg, expected)
      s.close()

    for netid in self.tuns:
      CheckTCPSYNPacket(4, netid, net_test.IPV4_ADDR)
      CheckTCPSYNPacket(6, netid, net_test.IPV6_ADDR)
      CheckTCPSYNPacket(6, netid, "::ffff:" + net_test.IPV4_ADDR)

    def CheckUDPPacket(version, netid, dstaddr):
      s = net_test.UDPSocket(self.GetProtocolFamily(version))
      self.SetSocketMark(s, netid)
      if version == 6 and dstaddr.startswith("::ffff"):
        version = 4
      myaddr = self._MyAddress(version, netid)
      desc, expected = Packets.UDP(version, myaddr, dstaddr, sport=None)
      msg = "IPv%s UDP %%s: expected %s on %s" % (
          version, desc, self._GetInterfaceName(netid))

      self.ClearTunQueues()
      s.sendto(UDP_PAYLOAD, (dstaddr, 53))
      self.ExpectPacketOn(netid, msg % "sendto", expected)

      self.ClearTunQueues()
      s.connect((dstaddr, 53))
      s.send(UDP_PAYLOAD)
      self.ExpectPacketOn(netid, msg % "connect/send", expected)
      s.close()

    for netid in self.tuns:
      CheckUDPPacket(4, netid, net_test.IPV4_ADDR)
      CheckUDPPacket(6, netid, net_test.IPV6_ADDR)
      CheckUDPPacket(6, netid, "::ffff:" + net_test.IPV4_ADDR)

  def CheckReflection(self, version, packet_generator, reply_generator,
                      callback=None):
    """Checks that replies go out on the same interface as the original.

    Iterates through all the combinations of the interfaces in self.tuns and the
    IP addresses assigned to them. For each combination:
     - Calls packet_generator to generate a packet to that IP address.
     - Writes the packet generated by packet_generator on the given tun
       interface, causing the kernel to receive it.
     - Checks that the kernel's reply matches the packet generated by
       reply_generator.
     - Calls the given callback function.

    Args:
      version: An integer, 4 or 6.
      packet_generator: A function taking an IP version (an integer), a source
        address and a destination address (strings), and returning a scapy
        packet.
      reply_generator: A function taking the same arguments as packet_generator,
        plus a scapy packet, and returning a scapy packet.
      callback: A function to call to perform extra checks if the packet
        matches. Takes netid, version, local address, remote address, original
        packet, kernel reply, and a message.
    """
    # Check packets addressed to the IP addresses of all our interfaces...
    for dest_ip_netid in self.tuns:
      dest_ip_iface = self._GetInterfaceName(dest_ip_netid)

      myaddr = self._MyAddress(version, dest_ip_netid)
      remote_addr = self._GetRemoteAddress(version)

      # ... coming in on all our interfaces.
      for iif_netid in self.tuns:
        iif = self._GetInterfaceName(iif_netid)
        desc, packet = packet_generator(version, remote_addr, myaddr)
        reply_desc, reply = reply_generator(version, myaddr, remote_addr,
                                            packet)
        msg = "Receiving %s on %s to %s IP: Expecting %s on %s" % (
            desc, iif, dest_ip_iface, reply_desc, iif)

        self.ClearTunQueues()
        # Cause the kernel to receive packet on iif_netid.
        self.ReceivePacketOn(iif_netid, packet)
        # Expect the kernel to send out reply on the same interface.
        reply = self.ExpectPacketOn(iif_netid, msg, reply)
        if callback:
          callback(iif_netid, version, myaddr, remote_addr, packet, reply, msg)

  def SYNToClosedPort(self, *args):
    return Packets.SYN(999, *args)

  def SYNToOpenPort(self, *args):
    return Packets.SYN(self.listenport, *args)

  def testIPv4ICMPErrorsReflectMark(self):
    self.CheckReflection(4, Packets.UDP, Packets.ICMPPortUnreachable)

  def testIPv6ICMPErrorsReflectMark(self):
    self.CheckReflection(6, Packets.UDP, Packets.ICMPPortUnreachable)

  def testIPv4PingRepliesReflectMarkAndTos(self):
    self.CheckReflection(4, Packets.ICMPEcho, Packets.ICMPReply)

  def testIPv6PingRepliesReflectMarkAndTos(self):
    self.CheckReflection(6, Packets.ICMPEcho, Packets.ICMPReply)

  def testIPv4RSTsReflectMark(self):
    self.CheckReflection(4, self.SYNToClosedPort, Packets.RST)

  def testIPv6RSTsReflectMark(self):
    self.CheckReflection(6, self.SYNToClosedPort, Packets.RST)

  def CheckAcceptedSocketMarkCallback(self, netid, version, myaddr,
                                      remote_addr, packet, reply, msg):
    establishing_ack = Packets.ACK(version, remote_addr, myaddr, reply)[1]
    self.ReceivePacketOn(netid, establishing_ack)
    s, unused_peer = self.listensocket.accept()
    try:
      mark = self.GetSocketMark(s)
    finally:
      s.close()
    self.assertEquals(netid, mark,
                      msg + ": Accepted socket: Expected mark %d, got %d" % (
                          netid, mark))

  def testIPv4SYNACKsReflectMark(self):
    self.CheckReflection(4, self.SYNToOpenPort, Packets.SYNACK,
                         self.CheckAcceptedSocketMarkCallback)

  def testIPv6SYNACKsReflectMark(self):
    self.CheckReflection(6, self.SYNToOpenPort, Packets.SYNACK,
                         self.CheckAcceptedSocketMarkCallback)

  def testSynCookiesSYNACKsReflectMark(self):
    # Force SYN cookies on all connections.
    open("/proc/sys/net/ipv4/tcp_syncookies", "w").write("2")
    try:
      self.CheckReflection(4, self.SYNToOpenPort, Packets.SYNACK,
                           self.CheckAcceptedSocketMarkCallback)
      self.CheckReflection(6, self.SYNToOpenPort, Packets.SYNACK,
                           self.CheckAcceptedSocketMarkCallback)
    finally:
      # Stop forcing SYN cookies on all connections.
      open("/proc/sys/net/ipv4/tcp_syncookies", "w").write("1")


if __name__ == "__main__":
  unittest.main()
