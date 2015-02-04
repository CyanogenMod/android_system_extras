#!/usr/bin/python

import errno
import fcntl
import os
import posix
import random
import re
from socket import *  # pylint: disable=wildcard-import
import struct
import unittest

from scapy import all as scapy

import iproute
import net_test

IFF_TUN = 1
IFF_TAP = 2
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

PING_IDENT = 0xff19
PING_PAYLOAD = "foobarbaz"
PING_SEQ = 3
PING_TOS = 0x83

UDP_PAYLOAD = "hello"


# Check to see if the kernel supports UID routing.
def HaveUidRouting():
  result = False

  # Create a rule with the UID selector. If the kernel doesn't understand the
  # UID selector, it will create a rule with no selectors.
  iproute.IPRoute().UidRule(6, True, 100, 100)

  # Dump dump all the rules. If we find a rule using the UID selector, then the
  # kernel supports UID routing.
  rules = iproute.IPRoute().DumpRules(6)
  for unused_rtmsg, attributes in rules:
    for (nla, unused_nla_data) in attributes:
      if nla.nla_type == iproute.EXPERIMENTAL_FRA_UID:
        result = True
        break

  # Delete the rule.
  iproute.IPRoute().UidRule(6, False, 100, 100)
  return result


AUTOCONF_TABLE_SYSCTL = "/proc/sys/net/ipv6/conf/default/accept_ra_rt_table"
IPV4_MARK_REFLECT_SYSCTL = "/proc/sys/net/ipv4/fwmark_reflect"
IPV6_MARK_REFLECT_SYSCTL = "/proc/sys/net/ipv6/fwmark_reflect"
SYNCOOKIES_SYSCTL = "/proc/sys/net/ipv4/tcp_syncookies"
TCP_MARK_ACCEPT_SYSCTL = "/proc/sys/net/ipv4/tcp_fwmark_accept"

HAVE_AUTOCONF_TABLE = os.path.isfile(AUTOCONF_TABLE_SYSCTL)
HAVE_MARK_REFLECT = os.path.isfile(IPV4_MARK_REFLECT_SYSCTL)
HAVE_TCP_MARK_ACCEPT = os.path.isfile(TCP_MARK_ACCEPT_SYSCTL)

HAVE_EXPERIMENTAL_UID_ROUTING = HaveUidRouting()


class ConfigurationError(AssertionError):
  pass


class UnexpectedPacketError(AssertionError):
  pass


class Packets(object):

  TCP_FIN = 1
  TCP_SYN = 2
  TCP_RST = 4
  TCP_ACK = 16

  TCP_SEQ = 1692871236
  TCP_WINDOW = 14400

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
                      flags=cls.TCP_SYN, window=cls.TCP_WINDOW))

  @classmethod
  def RST(cls, version, srcaddr, dstaddr, packet):
    ip = cls._GetIpLayer(version)
    original = packet.getlayer("TCP")
    return ("TCP RST",
            ip(src=srcaddr, dst=dstaddr) /
            scapy.TCP(sport=original.dport, dport=original.sport,
                      ack=original.seq + 1, seq=None,
                      flags=cls.TCP_RST | cls.TCP_ACK, window=cls.TCP_WINDOW))

  @classmethod
  def SYNACK(cls, version, srcaddr, dstaddr, packet):
    ip = cls._GetIpLayer(version)
    original = packet.getlayer("TCP")
    return ("TCP SYN+ACK",
            ip(src=srcaddr, dst=dstaddr) /
            scapy.TCP(sport=original.dport, dport=original.sport,
                      ack=original.seq + 1, seq=None,
                      flags=cls.TCP_SYN | cls.TCP_ACK, window=None))

  @classmethod
  def ACK(cls, version, srcaddr, dstaddr, packet):
    ip = cls._GetIpLayer(version)
    original = packet.getlayer("TCP")
    was_syn_or_fin = (original.flags & (cls.TCP_SYN | cls.TCP_FIN)) != 0
    return ("TCP ACK",
            ip(src=srcaddr, dst=dstaddr) /
            scapy.TCP(sport=original.dport, dport=original.sport,
                      ack=original.seq + was_syn_or_fin, seq=original.ack,
                      flags=cls.TCP_ACK, window=cls.TCP_WINDOW))

  @classmethod
  def FIN(cls, version, srcaddr, dstaddr, packet):
    ip = cls._GetIpLayer(version)
    original = packet.getlayer("TCP")
    was_fin = (original.flags & cls.TCP_FIN) != 0
    return ("TCP FIN",
            ip(src=srcaddr, dst=dstaddr) /
            scapy.TCP(sport=original.dport, dport=original.sport,
                      ack=original.seq + was_fin, seq=original.ack,
                      flags=cls.TCP_ACK | cls.TCP_FIN, window=cls.TCP_WINDOW))

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
  def ICMPPacketTooBig(cls, version, srcaddr, dstaddr, packet):
    if version == 4:
      # Linux hardcodes the ToS on ICMP errors to 0xc0 or greater because of
      # RFC 1812 4.3.2.5 (!).
      raise NotImplementedError
    else:
      udp = packet.getlayer("UDP")
      udp.payload = str(udp.payload)[:1280-40-8]
      return ("ICMPv6 Packet Too Big",
              scapy.IPv6(src=srcaddr, dst=dstaddr) /
              scapy.ICMPv6PacketTooBig() / str(packet)[:1232])

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


class RunAsUid(object):

  """Context guard to run a code block as a given UID."""

  def __init__(self, uid):
    self.uid = uid

  def __enter__(self):
    if self.uid:
      self.saved_uid = os.geteuid()
      if self.uid:
        os.seteuid(self.uid)

  def __exit__(self, unused_type, unused_value, unused_traceback):
    if self.uid:
      os.seteuid(self.saved_uid)


class MultiNetworkTest(net_test.NetworkTest):

  # Must be between 1 and 256, since we put them in MAC addresses and IIDs.
  NETIDS = [100, 150, 200, 250]

  # Stores sysctl values to write back when the test completes.
  saved_sysctls = {}

  # Wether to output setup commands.
  DEBUG = False

  @staticmethod
  def UidForNetid(netid):
    return 2000 + netid

  @classmethod
  def _TableForNetid(cls, netid):
    if cls.AUTOCONF_TABLE_OFFSET and netid in cls.ifindices:
      return cls.ifindices[netid] + (-cls.AUTOCONF_TABLE_OFFSET)
    else:
      return netid

  @staticmethod
  def GetInterfaceName(netid):
    return "nettest%d" % netid

  @staticmethod
  def RouterMacAddress(netid):
    return "02:00:00:00:%02x:00" % netid

  @staticmethod
  def MyMacAddress(netid):
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
    return net_test.GetLinkAddress(cls.GetInterfaceName(netid), False)

  @classmethod
  def MyAddress(cls, version, netid):
    return {4: cls._MyIPv4Address(netid),
            6: cls._MyIPv6Address(netid)}[version]

  @classmethod
  def CreateTunInterface(cls, netid):
    iface = cls.GetInterfaceName(netid)
    f = open("/dev/net/tun", "r+b")
    ifr = struct.pack("16sH", iface, IFF_TAP | IFF_NO_PI)
    ifr += "\x00" * (40 - len(ifr))
    fcntl.ioctl(f, TUNSETIFF, ifr)
    # Give ourselves a predictable MAC address.
    net_test.SetInterfaceHWAddr(iface, cls.MyMacAddress(netid))
    # Disable DAD so we don't have to wait for it.
    open("/proc/sys/net/ipv6/conf/%s/dad_transmits" % iface, "w").write("0")
    net_test.SetInterfaceUp(iface)
    net_test.SetNonBlocking(f)
    return f

  @classmethod
  def SendRA(cls, netid):
    validity = 300                 # seconds
    validity_ms = validity * 1000  # milliseconds
    macaddr = cls.RouterMacAddress(netid)
    lladdr = cls._RouterAddress(netid, 6)

    # We don't want any routes in the main table. If the kernel doesn't support
    # putting RA routes into per-interface tables, configure routing manually.
    routerlifetime = validity if HAVE_AUTOCONF_TABLE else 0

    ra = (scapy.Ether(src=macaddr, dst="33:33:00:00:00:01") /
          scapy.IPv6(src=lladdr, hlim=255) /
          scapy.ICMPv6ND_RA(retranstimer=validity_ms,
                            routerlifetime=routerlifetime) /
          scapy.ICMPv6NDOptSrcLLAddr(lladdr=macaddr) /
          scapy.ICMPv6NDOptPrefixInfo(prefix="2001:db8:%d::" % netid,
                                      prefixlen=64,
                                      L=1, A=1,
                                      validlifetime=validity,
                                      preferredlifetime=validity))
    posix.write(cls.tuns[netid].fileno(), str(ra))

  @classmethod
  def _RunSetupCommands(cls, netid, is_add):
    iptables_commands = [
        "/sbin/%(iptables)s %(append_delete)s INPUT -t mangle -i %(iface)s"
        " -j MARK --set-mark %(mark)d",
    ]
    route_commands = [
        "ip -%(version)d route %(add_del)s table %(table)s"
        " default dev %(iface)s via %(router)s",
    ]
    ipv4_commands = [
        "ip -4 nei %(add_del)s %(router)s dev %(iface)s"
        " lladdr %(macaddr)s nud permanent",
        "ip -4 addr %(add_del)s %(ipv4addr)s/24 dev %(iface)s",
    ]

    for version, iptables in zip([4, 6], ["iptables", "ip6tables"]):
      table = cls._TableForNetid(netid)
      uid = cls.UidForNetid(netid)
      iface = cls.GetInterfaceName(netid)
      if HAVE_EXPERIMENTAL_UID_ROUTING:
        cls.iproute.UidRule(version, is_add, uid, table, priority=100)
      cls.iproute.FwmarkRule(version, is_add, netid, table, priority=200)

      if cls.DEBUG:
        os.spawnvp(os.P_WAIT, "/sbin/ip", ["ip", "-6", "rule", "list"])

      if version == 6:
        if cls.AUTOCONF_TABLE_OFFSET is None:
          # Set up routing manually.
          cmds = iptables_commands + route_commands
        else:
          cmds = iptables_commands

      if version == 4:
        # Deleting addresses also causes routes to be deleted, so watch the
        # order or the test will output lots of ENOENT errors.
        if is_add:
          cmds = iptables_commands + ipv4_commands + route_commands
        else:
          cmds = iptables_commands + route_commands + ipv4_commands

      cmds = str("\n".join(cmds) % {
          "add_del": "add" if is_add else "del",
          "append_delete": "-A" if is_add else "-D",
          "iface": iface,
          "iptables": iptables,
          "ipv4addr": cls._MyIPv4Address(netid),
          "macaddr": cls.RouterMacAddress(netid),
          "mark": netid,
          "router": cls._RouterAddress(netid, version),
          "table": table,
          "version": version,
      }).split("\n")
      for cmd in cmds:
        cmd = cmd.split(" ")
        if cls.DEBUG: print " ".join(cmd)
        ret = os.spawnvp(os.P_WAIT, cmd[0], cmd)
        if ret:
          raise ConfigurationError("Setup command failed: %s" % " ".join(cmd))

  @classmethod
  def GetSysctl(cls, sysctl):
    return open(sysctl, "r").read()

  @classmethod
  def SetSysctl(cls, sysctl, value):
    # Only save each sysctl value the first time we set it. This is so we can
    # set it to arbitrary values multiple times and still write it back
    # correctly at the end.
    if sysctl not in cls.saved_sysctls:
      cls.saved_sysctls[sysctl] = cls.GetSysctl(sysctl)
    open(sysctl, "w").write(str(value) + "\n")

  @classmethod
  def _RestoreSysctls(cls):
    for sysctl, value in cls.saved_sysctls.iteritems():
      open(sysctl, "w").write(value)

  @classmethod
  def _ICMPRatelimitFilename(cls, version):
    return "/proc/sys/net/" + {4: "ipv4/icmp_ratelimit",
                               6: "ipv6/icmp/ratelimit"}[version]

  @classmethod
  def _SetICMPRatelimit(cls, version, limit):
    cls.SetSysctl(cls._ICMPRatelimitFilename(version), limit)

  @classmethod
  def setUpClass(cls):
    # This is per-class setup instead of per-testcase setup because shelling out
    # to ip and iptables is slow, and because routing configuration doesn't
    # change during the test.
    cls.iproute = iproute.IPRoute()
    cls.tuns = {}
    cls.ifindices = {}
    if HAVE_AUTOCONF_TABLE:
      cls.SetSysctl(AUTOCONF_TABLE_SYSCTL, -1000)
      cls.AUTOCONF_TABLE_OFFSET = -1000
    else:
      cls.AUTOCONF_TABLE_OFFSET = None

    # Disable ICMP rate limits. These will be restored by _RestoreSysctls.
    for version in [4, 6]:
      cls._SetICMPRatelimit(version, 0)

    for netid in cls.NETIDS:
      cls.tuns[netid] = cls.CreateTunInterface(netid)
      iface = cls.GetInterfaceName(netid)
      cls.ifindices[netid] = net_test.GetInterfaceIndex(iface)

      cls.SendRA(netid)
      cls._RunSetupCommands(netid, True)

    # Uncomment to look around at interface and rule configuration while
    # running in the background. (Once the test finishes running, all the
    # interfaces and rules are gone.)
    # time.sleep(30)

  @classmethod
  def tearDownClass(cls):
    for netid in cls.tuns:
      cls._RunSetupCommands(netid, False)
      cls.tuns[netid].close()
    cls._RestoreSysctls()

  def SetSocketMark(self, s, netid):
    s.setsockopt(SOL_SOCKET, net_test.SO_MARK, netid)

  def GetSocketMark(self, s):
    return s.getsockopt(SOL_SOCKET, net_test.SO_MARK)

  def ReceivePacketOn(self, netid, ip_packet):
    routermac = self.RouterMacAddress(netid)
    mymac = self.MyMacAddress(netid)
    packet = scapy.Ether(src=routermac, dst=mymac) / ip_packet
    posix.write(self.tuns[netid].fileno(), str(packet))

  def ReadAllPacketsOn(self, netid):
    packets = []
    while True:
      try:
        packet = posix.read(self.tuns[netid].fileno(), 4096)
        ether = scapy.Ether(packet)
        # Skip multicast frames, i.e., frames where the first byte of the
        # destination MAC address has 1 in the least-significant bit.
        if not int(ether.dst.split(":")[0], 16) & 0x1:
          packets.append(ether.payload)
      except OSError, e:
        # EAGAIN means there are no more packets waiting.
        if re.match(e.message, os.strerror(errno.EAGAIN)):
          break
        # Anything else is unexpected.
        else:
          raise e
    return packets

  def ClearTunQueues(self):
    # Keep reading packets on all netids until we get no packets on any of them.
    waiting = None
    while waiting != 0:
      waiting = sum(len(self.ReadAllPacketsOn(netid)) for netid in self.NETIDS)


class MarkTest(MultiNetworkTest):

  # How many times to run packet reflection tests.
  ITERATIONS = 5

  # For convenience.
  IPV4_ADDR = net_test.IPV4_ADDR
  IPV6_ADDR = net_test.IPV6_ADDR
  IPV4_PING = net_test.IPV4_PING
  IPV6_PING = net_test.IPV6_PING

  @classmethod
  def setUpClass(cls):
    super(MarkTest, cls).setUpClass()

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

  @classmethod
  def _SetMarkReflectSysctls(cls, value):
    cls.SetSysctl(IPV4_MARK_REFLECT_SYSCTL, value)
    try:
      cls.SetSysctl(IPV6_MARK_REFLECT_SYSCTL, value)
    except IOError:
      # This does not exist if we use the version of the patch that uses a
      # common sysctl for IPv4 and IPv6.
      pass

  @classmethod
  def _SetTCPMarkAcceptSysctl(cls, value):
    cls.SetSysctl(TCP_MARK_ACCEPT_SYSCTL, value)

  def assertPacketMatches(self, expected, actual):
    # The expected packet is just a rough sketch of the packet we expect to
    # receive. For example, it doesn't contain fields we can't predict, such as
    # initial TCP sequence numbers, or that depend on the host implementation
    # and settings, such as TCP options. To check whether the packet matches
    # what we expect, instead of just checking all the known fields one by one,
    # we blank out fields in the actual packet and then compare the whole
    # packets to each other as strings. Because we modify the actual packet,
    # make a copy here.
    actual = actual.copy()

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

  def ExpectNoPacketsOn(self, netid, msg, expected):
    packets = self.ReadAllPacketsOn(netid)
    if packets:
      firstpacket = str(packets[0]).encode("hex")
    else:
      firstpacket = ""
    self.assertFalse(packets, msg + ": unexpected packet: " + firstpacket)

  def ExpectPacketOn(self, netid, msg, expected):
    packets = self.ReadAllPacketsOn(netid)
    self.assertTrue(packets, msg + ": received no packets")

    # If we receive a packet that matches what we expected, return it.
    for packet in packets:
      if self.PacketMatches(expected, packet):
        return packet

    # None of the packets matched. Call assertPacketMatches to output a diff
    # between the expected packet and the last packet we received. In theory,
    # we'd output a diff to the packet that's the best match for what we
    # expected, but this is good enough for now.
    try:
      self.assertPacketMatches(expected, packets[-1])
    except Exception, e:
      raise UnexpectedPacketError(
          "%s: diff with last packet:\n%s" % (msg, e.message))

  def setUp(self):
    self.ClearTunQueues()

  def _GetRemoteAddress(self, version):
    return {4: self.IPV4_ADDR, 6: self.IPV6_ADDR}[version]

  def _GetProtocolFamily(self, version):
    return {4: AF_INET, 6: AF_INET6}[version]

  def BuildSocket(self, version, constructor, mark, uid):
    with RunAsUid(uid):
      family = self._GetProtocolFamily(version)
      s = constructor(family)
    if mark:
      self.SetSocketMark(s, mark)
    return s

  def CheckPingPacket(self, version, mark, uid, dstaddr, packet,
                      expected_netid):
    s = self.BuildSocket(version, net_test.PingSocket, mark, uid)

    myaddr = self.MyAddress(version, expected_netid)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind((myaddr, PING_IDENT))
    net_test.SetSocketTos(s, PING_TOS)

    desc, expected = Packets.ICMPEcho(version, myaddr, dstaddr)

    self.ClearTunQueues()
    s.sendto(packet + PING_PAYLOAD, (dstaddr, 19321))
    msg = "IPv%d ping: expected %s on %s" % (
        version, desc, self.GetInterfaceName(expected_netid))
    self.ExpectPacketOn(expected_netid, msg, expected)

  def CheckTCPSYNPacket(self, version, mark, uid, dstaddr, expected_netid):
    s = self.BuildSocket(version, net_test.TCPSocket, mark, uid)

    if version == 6 and dstaddr.startswith("::ffff"):
      version = 4
    myaddr = self.MyAddress(version, expected_netid)
    desc, expected = Packets.SYN(53, version, myaddr, dstaddr,
                                 sport=None, seq=None)

    self.ClearTunQueues()
    # Non-blocking TCP connects always return EINPROGRESS.
    self.assertRaisesErrno(errno.EINPROGRESS, s.connect, (dstaddr, 53))
    msg = "IPv%s TCP connect: expected %s on %s" % (
        version, desc, self.GetInterfaceName(expected_netid))
    self.ExpectPacketOn(expected_netid, msg, expected)
    s.close()

  def CheckUDPPacket(self, version, mark, uid, dstaddr, expected_netid):
    s = self.BuildSocket(version, net_test.UDPSocket, mark, uid)

    if version == 6 and dstaddr.startswith("::ffff"):
      version = 4
    myaddr = self.MyAddress(version, expected_netid)
    desc, expected = Packets.UDP(version, myaddr, dstaddr, sport=None)
    msg = "IPv%s UDP %%s: expected %s on %s" % (
        version, desc, self.GetInterfaceName(expected_netid))

    self.ClearTunQueues()
    s.sendto(UDP_PAYLOAD, (dstaddr, 53))
    self.ExpectPacketOn(expected_netid, msg % "sendto", expected)

    self.ClearTunQueues()
    s.connect((dstaddr, 53))
    s.send(UDP_PAYLOAD)
    self.ExpectPacketOn(expected_netid, msg % "connect/send", expected)
    s.close()

  def testMarkRouting(self):
    """Checks that socket marking selects the right outgoing interface."""
    for _ in xrange(self.ITERATIONS):
      for netid in self.tuns:
        self.CheckPingPacket(4, netid, 0, self.IPV4_ADDR, self.IPV4_PING, netid)
        self.CheckPingPacket(6, netid, 0, self.IPV6_ADDR, self.IPV6_PING, netid)

      for netid in self.tuns:
        self.CheckTCPSYNPacket(4, netid, 0, self.IPV4_ADDR, netid)
        self.CheckTCPSYNPacket(6, netid, 0, self.IPV6_ADDR, netid)
        self.CheckTCPSYNPacket(6, netid, 0, "::ffff:" + self.IPV4_ADDR, netid)

      for netid in self.tuns:
        self.CheckUDPPacket(4, netid, 0, self.IPV4_ADDR, netid)
        self.CheckUDPPacket(6, netid, 0, self.IPV6_ADDR, netid)
        self.CheckUDPPacket(6, netid, 0, "::ffff:" + self.IPV4_ADDR, netid)

  @unittest.skipUnless(HAVE_EXPERIMENTAL_UID_ROUTING, "no UID routing")
  def testUidRouting(self):
    """Checks that UID routing selects the right outgoing interface."""
    for _ in xrange(self.ITERATIONS):
      for netid in self.tuns:
        uid = self.UidForNetid(netid)
        self.CheckPingPacket(4, 0, uid, self.IPV4_ADDR, self.IPV4_PING, netid)
        self.CheckPingPacket(6, 0, uid, self.IPV6_ADDR, self.IPV6_PING, netid)

      for netid in self.tuns:
        uid = self.UidForNetid(netid)
        self.CheckTCPSYNPacket(4, 0, uid, self.IPV4_ADDR, netid)
        self.CheckTCPSYNPacket(6, 0, uid, self.IPV6_ADDR, netid)
        self.CheckTCPSYNPacket(6, 0, uid, "::ffff:" + self.IPV4_ADDR, netid)

      for netid in self.tuns:
        uid = self.UidForNetid(netid)
        self.CheckUDPPacket(4, 0, uid, self.IPV4_ADDR, netid)
        self.CheckUDPPacket(6, 0, uid, self.IPV6_ADDR, netid)
        self.CheckUDPPacket(6, 0, uid, "::ffff:" + self.IPV4_ADDR, netid)

  def CheckReflection(self, version, packet_generator, reply_generator,
                      mark_behaviour, callback=None):
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
      mark_behaviour: A string describing the mark behaviour to test. Tests are
        performed with the corresponding sysctl set to both 0 and 1.
      callback: A function to call to perform extra checks if the packet
        matches. Takes netid, version, local address, remote address, original
        packet, kernel reply, and a message.
    """
    # What are we testing?
    sysctl_function = {"accept": self._SetTCPMarkAcceptSysctl,
                       "reflect": self._SetMarkReflectSysctls}[mark_behaviour]

    # Check packets addressed to the IP addresses of all our interfaces...
    for dest_ip_netid in self.tuns:
      dest_ip_iface = self.GetInterfaceName(dest_ip_netid)

      myaddr = self.MyAddress(version, dest_ip_netid)
      remote_addr = self._GetRemoteAddress(version)

      # ... coming in on all our interfaces...
      for iif_netid in self.tuns:
        iif = self.GetInterfaceName(iif_netid)
        desc, packet = packet_generator(version, remote_addr, myaddr)
        reply_desc, reply = reply_generator(version, myaddr, remote_addr,
                                            packet)

        # ... with inbound mark sysctl enabled and disabled.
        for sysctl_value in [0, 1]:
          msg = "Receiving %s on %s to %s IP, %s=%d" % (
              desc, iif, dest_ip_iface, mark_behaviour, sysctl_value)
          sysctl_function(sysctl_value)
          self.ClearTunQueues()
          # Cause the kernel to receive packet on iif_netid.
          self.ReceivePacketOn(iif_netid, packet)
          # Expect the kernel to send out reply on the same interface.
          if sysctl_value:
            msg += ": Expecting %s on %s" % (reply_desc, iif)
            reply = self.ExpectPacketOn(iif_netid, msg, reply)
            if callback:
              callback(iif_netid, version, myaddr, remote_addr, packet, reply,
                       msg)
          else:
            msg += ": Expecting no packets on %s" % reply_desc
            self.ExpectNoPacketsOn(iif_netid, msg, reply)

  def SYNToClosedPort(self, *args):
    return Packets.SYN(999, *args)

  def SYNToOpenPort(self, *args):
    return Packets.SYN(self.listenport, *args)

  @unittest.skipUnless(HAVE_MARK_REFLECT, "no mark reflection")
  def testIPv4ICMPErrorsReflectMark(self):
    self.CheckReflection(4, Packets.UDP, Packets.ICMPPortUnreachable, "reflect")

  @unittest.skipUnless(HAVE_MARK_REFLECT, "no mark reflection")
  def testIPv6ICMPErrorsReflectMark(self):
    self.CheckReflection(6, Packets.UDP, Packets.ICMPPortUnreachable, "reflect")

  @unittest.skipUnless(HAVE_MARK_REFLECT, "no mark reflection")
  def testIPv4PingRepliesReflectMarkAndTos(self):
    self.CheckReflection(4, Packets.ICMPEcho, Packets.ICMPReply, "reflect")

  @unittest.skipUnless(HAVE_MARK_REFLECT, "no mark reflection")
  def testIPv6PingRepliesReflectMarkAndTos(self):
    self.CheckReflection(6, Packets.ICMPEcho, Packets.ICMPReply, "reflect")

  @unittest.skipUnless(HAVE_MARK_REFLECT, "no mark reflection")
  def testIPv4RSTsReflectMark(self):
    self.CheckReflection(4, self.SYNToClosedPort, Packets.RST, "reflect")

  @unittest.skipUnless(HAVE_MARK_REFLECT, "no mark reflection")
  def testIPv6RSTsReflectMark(self):
    self.CheckReflection(6, self.SYNToClosedPort, Packets.RST, "reflect")

  def CheckTCPConnection(self, netid, version, myaddr, remote_addr,
                         packet, reply, msg):
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

    # Check the FIN was sent on the right interface, and ack it. We don't expect
    # this to fail because by the time the connection is established things are
    # likely working, but a) extra tests are always good and b) extra packets
    # like the FIN (and retransmitted FINs) could cause later tests that expect
    # no packets to fail.
    desc, fin = Packets.FIN(version, myaddr, remote_addr, establishing_ack)
    self.ExpectPacketOn(netid, msg + ": expecting %s after close" % desc, fin)

    desc, finack = Packets.FIN(version, remote_addr, myaddr, fin)
    self.ReceivePacketOn(netid, finack)

    desc, finackack = Packets.ACK(version, myaddr, remote_addr, finack)
    self.ExpectPacketOn(netid, msg + ": expecting final ack", finackack)

  @unittest.skipUnless(HAVE_TCP_MARK_ACCEPT, "fwmark writeback not supported")
  def testIPv4TCPConnections(self):
    self.CheckReflection(4, self.SYNToOpenPort, Packets.SYNACK, "accept",
                         self.CheckTCPConnection)

  @unittest.skipUnless(HAVE_TCP_MARK_ACCEPT, "fwmark writeback not supported")
  def testIPv6TCPConnections(self):
    self.CheckReflection(6, self.SYNToOpenPort, Packets.SYNACK, "accept",
                         self.CheckTCPConnection)

  @unittest.skipUnless(HAVE_TCP_MARK_ACCEPT, "fwmark writeback not supported")
  def testTCPConnectionsWithSynCookies(self):
    # Force SYN cookies on all connections.
    self.SetSysctl(SYNCOOKIES_SYSCTL, 2)
    try:
      self.CheckReflection(4, self.SYNToOpenPort, Packets.SYNACK, "accept",
                           self.CheckTCPConnection)
      self.CheckReflection(6, self.SYNToOpenPort, Packets.SYNACK, "accept",
                           self.CheckTCPConnection)
    finally:
      # Stop forcing SYN cookies on all connections.
      self.SetSysctl(SYNCOOKIES_SYSCTL, 1)


class RATest(MultiNetworkTest):

  def testDoesNotHaveObsoleteSysctl(self):
    self.assertFalse(os.path.isfile(
        "/proc/sys/net/ipv6/route/autoconf_table_offset"))

  def testPurgeDefaultRouters(self):

    def CheckIPv6Connectivity(expect_connectivity):
      for netid in self.NETIDS:
        s = net_test.UDPSocket(AF_INET6)
        self.SetSocketMark(s, netid)
        if expect_connectivity:
          self.assertEquals(5, s.sendto("hello", (net_test.IPV6_ADDR, 1234)))
        else:
          self.assertRaisesErrno(errno.ENETUNREACH,
                                 s.sendto, "hello", (net_test.IPV6_ADDR, 1234))

    try:
      CheckIPv6Connectivity(True)
      self.SetSysctl("/proc/sys/net/ipv6/conf/all/forwarding", 1)
      CheckIPv6Connectivity(False)
    finally:
      self.SetSysctl("/proc/sys/net/ipv6/conf/all/forwarding", 0)
      for netid in self.NETIDS:
        self.SendRA(netid)
      CheckIPv6Connectivity(True)

  @unittest.skipUnless(False, "Known bug: routing tables are never deleted")
  def testNoLeftoverRoutes(self):
    def GetNumRoutes():
      return len(open("/proc/net/ipv6_route").readlines())

    num_routes = GetNumRoutes()
    for i in xrange(10, 20):
      try:
        self.tuns[i] = self.CreateTunInterface(i)
        self.SendRA(i)
        self.tuns[i].close()
      finally:
        del self.tuns[i]
    self.assertEquals(num_routes, GetNumRoutes())


class RedirectAndPMTUTest(MultiNetworkTest):

  IPV6_PATHMTU = 61
  IPV6_DONTFRAG = 62

  def GetRandomDestination(self, version):
    if version == 4:
      return "172.16.%d.%d" % (random.randint(0, 31), random.randint(0, 255))
    else:
      return "2001:db8::%x:%x" % (random.randint(0, 65535),
                                  random.randint(0, 65535))

  def GetSocketMTU(self, s):
    ip6_mtuinfo = s.getsockopt(net_test.SOL_IPV6, self.IPV6_PATHMTU, 32)
    mtu = struct.unpack("=28sI", ip6_mtuinfo)
    return mtu[1]

  def testIPv6PMTU(self):
    s = net_test.Socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    s.setsockopt(net_test.SOL_IPV6, self.IPV6_DONTFRAG, 1)
    s.setsockopt(net_test.SOL_IPV6, net_test.IPV6_RECVERR, 1)
    netid = self.NETIDS[2]  # Just pick an arbitrary one.

    srcaddr = self.MyAddress(6, netid)
    dstaddr = self.GetRandomDestination(6)
    intermediate = "2001:db8::1"

    self.SetSocketMark(s, netid)  # So the packet has somewhere to go.
    s.connect((dstaddr, 1234))
    self.assertEquals(1500, self.GetSocketMTU(s))

    self.ClearTunQueues()
    s.send(1400 * "a")
    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    toobig = Packets.ICMPPacketTooBig(6, intermediate, srcaddr, packets[0])[1]
    self.ReceivePacketOn(netid, toobig)
    self.assertEquals(1280, self.GetSocketMTU(s))


if __name__ == "__main__":
  unittest.main()
