#!/usr/bin/python

import fcntl
import errno
import os
import posix
import struct
import time
import unittest
from scapy import all as scapy
from socket import *

import net_test

DEBUG = False

IFF_TUN = 1
IFF_TAP = 2
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

AUTOCONF_TABLE_SYSCTL = "/proc/sys/net/ipv6/route/autoconf_table_offset"

class ConfigurationError(AssertionError):
  pass


class UnexpectedPacketError(AssertionError):
  pass


class Packets(object):

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
  def UdpPacket(self, version, srcaddr, dstaddr):
    ip = self._GetIpLayer(version)
    return ("UDPv%d packet" % version,
            ip(src=srcaddr, dst=dstaddr) /
            scapy.UDP(sport=999, dport=1234) / "hello")

  @classmethod
  def SYN(self, port, version, srcaddr, dstaddr):
    ip = self._GetIpLayer(version)
    return ("TCP SYN",
            ip(src=srcaddr, dst=dstaddr) /
            scapy.TCP(sport=50999, dport=port, seq=1692871236, ack=0,
                      flags=2, window=14400))

  @classmethod
  def RST(self, version, srcaddr, dstaddr, packet):
    ip = self._GetIpLayer(version)
    original = packet.getlayer("TCP")
    return ("TCP RST",
            ip(src=srcaddr, dst=dstaddr) /
            scapy.TCP(sport=original.dport, dport=original.sport,
                      ack=original.seq + 1, seq=None,
                      flags=20, window=None))

  @classmethod
  def SYNACK(self, version, srcaddr, dstaddr, packet):
    ip = self._GetIpLayer(version)
    original = packet.getlayer("TCP")
    return ("TCP SYN+ACK",
            ip(src=srcaddr, dst=dstaddr) /
            scapy.TCP(sport=original.dport, dport=original.sport,
                      ack=original.seq + 1, seq=None,
                      flags=18, window=None))

  @classmethod
  def ICMPPortUnreachable(self, version, srcaddr, dstaddr, packet):
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
  def ICMPEcho(self, version, srcaddr, dstaddr):
    ip = self._GetIpLayer(version)
    icmp = {4: scapy.ICMP, 6: scapy.ICMPv6EchoRequest}[version]
    packet = (ip(src=srcaddr, dst=dstaddr) /
              icmp(id=0xff19, seq=3) / "foobarbaz")
    self._SetPacketTos(packet, 0x83)
    return ("ICMPv%d echo" % version, packet)

  @classmethod
  def ICMPReply(self, version, srcaddr, dstaddr, packet, tos=None):
    ip = self._GetIpLayer(version)

    # Scapy doesn't provide an ICMP echo reply constructor.
    icmpv4_reply = lambda **kwargs: scapy.ICMP(type=0, **kwargs)
    icmp = {4: icmpv4_reply, 6: scapy.ICMPv6EchoReply}[version]
    packet = (ip(src=srcaddr, dst=dstaddr) /
              icmp(id=0xff19, seq=3) / "foobarbaz")
    self._SetPacketTos(packet, 0x83)
    return ("ICMPv%d echo" % version, packet)


class MarkTest(net_test.NetworkTest):

  NETIDS = [100, 200]

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

  @staticmethod
  def _MyIPv4Address(netid):
    return "10.0.%d.2" % netid

  @classmethod
  def _CreateTunInterface(self, netid):
    iface = self._GetInterfaceName(netid)
    f = open("/dev/net/tun", "r+b")
    ifr = struct.pack("16sH", iface, IFF_TAP | IFF_NO_PI)
    ifr = ifr + "\x00" * (40 - len(ifr))
    fcntl.ioctl(f, TUNSETIFF, ifr)
    # Give ourselves a predictable MAC address.
    macaddr = self._MyMacAddress(netid)
    net_test.SetInterfaceHWAddr(iface, self._MyMacAddress(netid))
    # Disable DAD so we don't have to wait for it.
    open("/proc/sys/net/ipv6/conf/%s/dad_transmits" % iface, "w").write("0")
    net_test.SetInterfaceUp(iface)
    net_test.SetNonBlocking(f)
    return f

  @staticmethod
  def _GetInterfaceName(netid):
    return "nettest%d" % netid

  @classmethod
  def _SendRA(self, netid):
    validity = 300                 # seconds
    validity_ms = validity * 1000  # milliseconds
    macaddr = self._RouterMacAddress(netid)
    lladdr = self._RouterAddress(netid, 6)
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
    posix.write(self.tuns[netid].fileno(), str(ra))

  COMMANDS = [
      "/sbin/%(iptables)s %(append_delete)s INPUT -t mangle -i %(iface)s"
      " -j MARK --set-mark %(netid)d",
      "ip -%(version)d rule %(add_del)s fwmark %(netid)s lookup %(table)s",
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
  def _RunSetupCommands(self, netid, is_add):
    iface = self._GetInterfaceName(netid)
    for version, iptables in zip([4, 6], ["iptables", "ip6tables"]):

      if version == 6:
        cmds = self.COMMANDS
        if self.AUTOCONF_TABLE_OFFSET < 0:
          # Set up routing manually.
          # Don't do cmds += self.ROUTE_COMMANDS as this modifies self.COMMANDS.
          cmds = self.COMMANDS + self.ROUTE_COMMANDS

      if version == 4:
        # Deleting addresses also causes routes to be deleted, so watch the
        # order or the test will output lots of ENOENT errors.
        if is_add:
          cmds = self.COMMANDS + self.IPV4_COMMANDS + self.ROUTE_COMMANDS
        else:
          cmds = self.COMMANDS + self.ROUTE_COMMANDS + self.IPV4_COMMANDS

      cmds = str("\n".join(cmds) % {
          "add_del": "add" if is_add else "del",
          "append_delete": "-A" if is_add else "-D",
          "iface": iface,
          "iptables": iptables,
          "ipv4addr": self._MyIPv4Address(netid),
          "macaddr": self._RouterMacAddress(netid),
          "netid": netid,
          "router": self._RouterAddress(netid, version),
          "table": self._TableForNetid(netid),
          "version": version,
      }).split("\n")
      for cmd in cmds:
        cmd = cmd.split(" ")
        if DEBUG: print " ".join(cmd)
        ret = os.spawnvp(os.P_WAIT, cmd[0], cmd)
        if ret:
          raise ConfigurationError("Setup command failed: %s" % " ".join(cmd))

  @classmethod
  def _SetAutoconfTableSysctl(self, offset):
    try:
      open(AUTOCONF_TABLE_SYSCTL, "w").write(str(offset))
      self.AUTOCONF_TABLE_OFFSET = offset
    except IOError:
      self.AUTOCONF_TABLE_OFFSET = -1

  @classmethod
  def _TableForNetid(self, netid):
    if self.AUTOCONF_TABLE_OFFSET >= 0:
      return self.ifindices[netid] + self.AUTOCONF_TABLE_OFFSET
    else:
      return netid      

  @classmethod
  def setUpClass(self):
    self.tuns = {}
    self.ifindices = {}
    self._SetAutoconfTableSysctl(1000)
    for netid in self.NETIDS:
      self.tuns[netid] = self._CreateTunInterface(netid)

      iface = self._GetInterfaceName(netid)
      self.ifindices[netid] = net_test.GetInterfaceIndex(iface)

      self._SendRA(netid)
      self._RunSetupCommands(netid, True)

    # Open a port so we can observe SYN+ACKs. Since it's a dual-stack socket it
    # will accept both IPv4 and IPv6 connections. We do this here instead of in
    # each test so we can use the same socket every time. That way, if a kernel
    # bug causes incoming packets to mark the listening socket instead of the
    # accepted socket, the test will fail as soon as the next address/interface
    # combination is tried.
    self.listenport = 1234
    self.listensocket = net_test.IPv6TCPSocket()
    self.listensocket.bind(("::", self.listenport))
    self.listensocket.listen(100)

    # Give time for unknown things to settle down.
    time.sleep(0.5)
    # Uncomment to look around at interface and rule configuration while
    # running in the background. (Once the test finishes running, all the
    # interfaces and rules are gone.)
    #time.sleep(30)

  @classmethod
  def tearDownClass(self):
    for netid in self.tuns:
      self._RunSetupCommands(netid, False)
      self.tuns[netid].close()

  def CheckExpectedPacket(self, expected, actual, msg):
      # Remove the Ethernet header from the incoming packet.
      actual = scapy.Ether(actual).payload

      # Blank out IPv4 fields that we can't predict, like ID and the DF bit.
      actualip = actual.getlayer("IP")
      expectedip = expected.getlayer("IP")
      if actualip and expectedip:
        actualip.id = expectedip.id
        actualip.flags &= 5
        actualip.chksum = None  # Change the header, recalculate the checksum.

      # Blank out TCP fields that we can't predict.
      actualtcp = actual.getlayer("TCP")
      expectedtcp = expected.getlayer("TCP")
      if actualtcp and expectedtcp:
        actualtcp.dataofs = expectedtcp.dataofs
        actualtcp.options = expectedtcp.options
        actualtcp.window = expectedtcp.window
        if expectedtcp.seq is None:
          actualtcp.seq = None
        if expectedtcp.ack is None:
          actualtcp.ack = None
        actualtcp.chksum = None

      # Serialize the packet so:
      # - Expected packet fields that are only set when a packet is serialized
      #   (e.g., the checksum) are filled in.
      # - The packet is readable. Scapy has detailed dissection capabilities,
      #   but they only seem to be usable to print the packet, not return its
      #   dissection as a string.
      #   TODO: Check if this is true.
      self.assertMultiLineEqual(str(expected).encode("hex"),
                                str(actual).encode("hex"))
    
  def assertNoPacketsOn(self, netids, msg):
    for netid in netids:
      try:
        self.assertRaisesErrno(errno.EAGAIN, self.tuns[netid].read, 4096)
      except AssertionError, e:
        raise UnexpectedPacketError("%s: Unexpected packet on %s" % (
            msg, self._GetInterfaceName(netid)))

  def assertNoOtherPackets(self, msg):
    self.assertNoPacketsOn([netid for netid in self.tuns], msg)

  def assertNoPacketsExceptOn(self, netid, msg):
    self.assertNoPacketsOn([n for n in self.tuns if n != netid], msg)

  def ExpectPacketOn(self, netid, msg, expected=None):
    # Check no packets were sent on any other netid.
    self.assertNoPacketsExceptOn(netid, msg)

    # Check that a packet was sent on netid.
    try:
      actual = self.tuns[netid].read(4096)
    except IOError, e:
      raise AssertionError(msg + ": " + str(e))
    self.assertTrue(actual)

    # If we know what sort of packet we expect, check that here.
    if expected:
      self.CheckExpectedPacket(expected, actual, msg)

  def ReceivePacketOn(self, netid, ip_packet):
    routermac = self._RouterMacAddress(netid)
    mymac = self._MyMacAddress(netid)
    packet = scapy.Ether(src=routermac, dst=mymac) / ip_packet
    posix.write(self.tuns[netid].fileno(), str(packet))

  def ClearTunQueues(self):
    for f in self.tuns.values():
      try:
        f.read(4096)
      except IOError:
        continue
    self.assertNoOtherPackets("Unexpected packets after clearing queues")

  def setUp(self):
    self.ClearTunQueues()

  @staticmethod
  def _GetRemoteAddress(version):
    return {4: net_test.IPV4_ADDR, 6: net_test.IPV6_ADDR}[version]

  def MarkSocket(self, s, netid):
    s.setsockopt(SOL_SOCKET, net_test.SO_MARK, netid)

  def GetProtocolFamily(self, version):
    return {4: AF_INET, 6: AF_INET6}[version]

  def testOutgoingPackets(self):
    """Checks that socket marking selects the right outgoing interface."""

    def CheckPingPacket(version, netid, packet):
      s = net_test.PingSocket(self.GetProtocolFamily(version))
      dstaddr = self._GetRemoteAddress(version)
      self.MarkSocket(s, netid)
      s.sendto(packet, (dstaddr, 19321))
      self.ExpectPacketOn(netid, "IPv%d ping: mark %d" % (version, netid))

    for netid in self.tuns:
      CheckPingPacket(4, netid, net_test.IPV4_PING)
      CheckPingPacket(6, netid, net_test.IPV6_PING)

    def CheckTCPSYNPacket(version, netid, dstaddr):
      s = net_test.TCPSocket(self.GetProtocolFamily(version))
      self.MarkSocket(s, netid)
      # Non-blocking TCP connects always return EINPROGRESS.
      self.assertRaisesErrno(errno.EINPROGRESS, s.connect, (dstaddr, 53))
      self.ExpectPacketOn(netid, "IPv%d TCP connect: mark %d" % (version,
                                                                 netid))
      s.close()

    for netid in self.tuns:
      CheckTCPSYNPacket(4, netid, net_test.IPV4_ADDR)
      CheckTCPSYNPacket(6, netid, net_test.IPV6_ADDR)
      CheckTCPSYNPacket(6, netid, "::ffff:" + net_test.IPV4_ADDR)

    def CheckUDPPacket(version, netid, dstaddr):
      s = net_test.UDPSocket(self.GetProtocolFamily(version))
      self.MarkSocket(s, netid)
      s.sendto("hello", (dstaddr, 53))
      self.ExpectPacketOn(netid, "IPv%d UDP sendto: mark %d" % (version, netid))
      s.connect((dstaddr, 53))
      s.send("hello")
      self.ExpectPacketOn(netid, "IPv%d UDP connect/send: mark %d" % (version,
                                                                      netid))
      s.close()

    for netid in self.tuns:
      CheckUDPPacket(4, netid, net_test.IPV4_ADDR)
      CheckUDPPacket(6, netid, net_test.IPV6_ADDR)
      CheckUDPPacket(6, netid, "::ffff:" + net_test.IPV4_ADDR)

  def CheckReflection(self, version, packet_generator, reply_generator):
    """Checks that replies go out on the same interface as the original."""

    # Check packets addressed to the IP addresses of all our interfaces...
    for dest_ip_netid in self.tuns:
      dest_ip_iface = self._GetInterfaceName(dest_ip_netid)

      if version == 4:
        myaddr = self._MyIPv4Address(dest_ip_netid)
      else:
        myaddr = net_test.GetLinkAddress(self._GetInterfaceName(dest_ip_netid),
                                                                False)
      remote_addr = self._GetRemoteAddress(version)

      # ... coming in on all our interfaces.
      for iif_netid in self.tuns:
        iif = self._GetInterfaceName(iif_netid)
        desc, packet = packet_generator(version, remote_addr, myaddr)
        if reply_generator:
          # We know what we want a reply to.
          reply_desc, reply = reply_generator(version, myaddr, remote_addr,
                                              packet)
        else:
          # Expect any reply.
          reply_desc, reply = "any packet", None
        msg = "Receiving %s on %s to %s IP: Expecting %s on %s" % (
            desc, iif, dest_ip_iface, reply_desc, iif)

        # Expect a reply on the interface the original packet came in on.
        self.ClearTunQueues()
        self.ReceivePacketOn(iif_netid, packet)
        self.ExpectPacketOn(iif_netid, msg, reply)

  def SYNToClosedPort(self, *args):
    return Packets.SYN(999, *args)

  def SYNToOpenPort(self, *args):
    return Packets.SYN(self.listenport, *args)

  def testIPv4ICMPErrorsReflectMark(self):
    self.CheckReflection(4, Packets.UdpPacket, Packets.ICMPPortUnreachable)

  def testIPv6ICMPErrorsReflectMark(self):
    self.CheckReflection(6, Packets.UdpPacket, Packets.ICMPPortUnreachable)

  def testIPv4PingRepliesReflectMarkAndTos(self):
    self.CheckReflection(4, Packets.ICMPEcho, Packets.ICMPReply)

  def testIPv6PingRepliesReflectMarkAndTos(self):
    self.CheckReflection(6, Packets.ICMPEcho, Packets.ICMPReply)

  def testIPv4RSTsReflectMark(self):
    self.CheckReflection(4, self.SYNToClosedPort, Packets.RST)

  def testIPv6RSTsReflectMark(self):
    self.CheckReflection(6, self.SYNToClosedPort, Packets.RST)

  @unittest.skipUnless(False, "skipping: doesn't work yet")
  def testIPv4SYNACKsReflectMark(self):
    self.CheckReflection(4, Packets.SYNToOpenPort, Packets.SYNACK)

  @unittest.skipUnless(False, "skipping: doesn't work yet")
  def testIPv6SYNACKsReflectMark(self):
    self.CheckReflection(6, Packets.SYNToOpenPort, Packets.SYNACK)


if __name__ == "__main__":
  unittest.main()
