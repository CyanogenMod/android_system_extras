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

SO_BINDTODEVICE = 25

UDP_PAYLOAD = "hello"


# Check to see if the kernel supports UID routing.
def HaveUidRouting():
  # Create a rule with the UID range selector. If the kernel doesn't understand
  # the selector, it will create a rule with no selectors.
  iproute.IPRoute().UidRangeRule(6, True, 1000, 2000, 100)

  # Dump all the rules. If we find a rule using the UID range selector, then the
  # kernel supports UID range routing.
  rules = iproute.IPRoute().DumpRules(6)
  result = any(iproute.EXPERIMENTAL_FRA_UID_START in attrs
               for rule, attrs in rules)

  # Delete the rule.
  iproute.IPRoute().UidRangeRule(6, False, 1000, 2000, 100)
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
    return ("ICMPv%d echo reply" % version, packet)

  @classmethod
  def NS(cls, srcaddr, tgtaddr, srcmac):
    solicited = inet_pton(AF_INET6, tgtaddr)
    last3bytes = tuple([ord(b) for b in solicited[-3:]])
    solicited = "ff02::1:ff%02x:%02x%02x" % last3bytes
    packet = (scapy.IPv6(src=srcaddr, dst=solicited) /
              scapy.ICMPv6ND_NS(tgt=tgtaddr) /
              scapy.ICMPv6NDOptSrcLLAddr(lladdr=srcmac))
    return ("ICMPv6 NS", packet)

  @classmethod
  def NA(cls, srcaddr, dstaddr, srcmac):
    packet = (scapy.IPv6(src=srcaddr, dst=dstaddr) /
              scapy.ICMPv6ND_NA(tgt=srcaddr, R=0, S=1, O=1) /
              scapy.ICMPv6NDOptDstLLAddr(lladdr=srcmac))
    return ("ICMPv6 NA", packet)


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

  # The size of our UID ranges.
  UID_RANGE_SIZE = 1000

  @classmethod
  def UidRangeForNetid(cls, netid):
    return (
        cls.UID_RANGE_SIZE * netid,
        cls.UID_RANGE_SIZE * (netid + 1) - 1
    )

  @classmethod
  def UidForNetid(cls, netid):
    return random.randint(*cls.UidRangeForNetid(netid))

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

  @staticmethod
  def IPv6Prefix(netid):
    return "2001:db8:%02x::" % netid

  @staticmethod
  def GetRandomDestination(prefix):
    if "." in prefix:
      return prefix + "%d.%d" % (random.randint(0, 31), random.randint(0, 255))
    else:
      return prefix + "%x:%x" % (random.randint(0, 65535),
                                 random.randint(0, 65535))

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
    cls.SetSysctl("/proc/sys/net/ipv6/conf/%s/accept_dad" % iface, 0)
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
          scapy.ICMPv6NDOptPrefixInfo(prefix=cls.IPv6Prefix(netid),
                                      prefixlen=64,
                                      L=1, A=1,
                                      validlifetime=validity,
                                      preferredlifetime=validity))
    posix.write(cls.tuns[netid].fileno(), str(ra))

  @classmethod
  def _RunSetupCommands(cls, netid, is_add):
    for version in [4, 6]:
      # Find out how to configure things.
      iface = cls.GetInterfaceName(netid)
      ifindex = cls.ifindices[netid]
      macaddr = cls.RouterMacAddress(netid)
      router = cls._RouterAddress(netid, version)
      table = cls._TableForNetid(netid)

      # Run iptables to set up incoming packet marking.
      add_del = "-A" if is_add else "-D"
      iptables = {4: "iptables", 6: "ip6tables"}[version]
      args = "%s %s INPUT -t mangle -i %s -j MARK --set-mark %d" % (
          iptables, add_del, iface, netid)
      iptables = "/sbin/" + iptables
      ret = os.spawnvp(os.P_WAIT, iptables, args.split(" "))
      if ret:
        raise ConfigurationError("Setup command failed: %s" % args)

      # Set up routing rules.
      if HAVE_EXPERIMENTAL_UID_ROUTING:
        start, end = cls.UidRangeForNetid(netid)
        cls.iproute.UidRangeRule(version, is_add, start, end, table,
                                 priority=100)
      cls.iproute.OifRule(version, is_add, iface, table, priority=200)
      cls.iproute.FwmarkRule(version, is_add, netid, table, priority=300)

      # Configure routing and addressing.
      #
      # IPv6 uses autoconf for everything, except if per-device autoconf routing
      # tables are not supported, in which case the default route (only) is
      # configured manually. For IPv4 we have to manualy configure addresses,
      # routes, and neighbour cache entries (since we don't reply to ARP or ND).
      #
      # Since deleting addresses also causes routes to be deleted, we need to
      # be careful with ordering or the delete commands will fail with ENOENT.
      do_routing = (version == 4 or cls.AUTOCONF_TABLE_OFFSET is None)
      if is_add:
        if version == 4:
          cls.iproute.AddAddress(cls._MyIPv4Address(netid), 24, ifindex)
          cls.iproute.AddNeighbour(version, router, macaddr, ifindex)
        if do_routing:
          cls.iproute.AddRoute(version, table, "default", 0, router, ifindex)
      else:
        if do_routing:
          cls.iproute.DelRoute(version, table, "default", 0, router, ifindex)
        if version == 4:
          cls.iproute.DelNeighbour(version, router, macaddr, ifindex)
          cls.iproute.DelAddress(cls._MyIPv4Address(netid), 24, ifindex)

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
      try:
        open(sysctl, "w").write(value)
      except IOError:
        pass

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

  def ClearSocketMark(self, s):
    self.SetSocketMark(s, 0)

  def BindToDevice(self, s, iface):
    if not iface:
      iface = ""
    s.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, iface)

  def ReceiveEtherPacketOn(self, netid, packet):
    posix.write(self.tuns[netid].fileno(), str(packet))

  def ReceivePacketOn(self, netid, ip_packet):
    routermac = self.RouterMacAddress(netid)
    mymac = self.MyMacAddress(netid)
    packet = scapy.Ether(src=routermac, dst=mymac) / ip_packet
    self.ReceiveEtherPacketOn(netid, packet)

  def ReadAllPacketsOn(self, netid, include_multicast=False):
    packets = []
    while True:
      try:
        packet = posix.read(self.tuns[netid].fileno(), 4096)
        ether = scapy.Ether(packet)
        # Multicast frames are frames where the first byte of the destination
        # MAC address has 1 in the least-significant bit.
        if include_multicast or not int(ether.dst.split(":")[0], 16) & 0x1:
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

    # Serialize the packet so that expected packet fields that are only set when
    # a packet is serialized e.g., the checksum) are filled in.
    expected_real = expected.__class__(str(expected))
    actual_real = actual.__class__(str(actual))
    # repr() can be expensive. Call it only if the test is going to fail and we
    # want to see the error.
    if expected_real != actual_real:
      self.assertEquals(repr(expected_real), repr(actual_real))

  def PacketMatches(self, expected, actual):
    try:
      self.assertPacketMatches(expected, actual)
      return True
    except AssertionError:
      return False

  def ExpectNoPacketsOn(self, netid, msg):
    packets = self.ReadAllPacketsOn(netid)
    if packets:
      firstpacket = str(packets[0]).encode("hex")
    else:
      firstpacket = ""
    self.assertFalse(packets, msg + ": unexpected packet: " + firstpacket)

  def ExpectPacketOn(self, netid, msg, expected):
    # To avoid confusion due to lots of ICMPv6 ND going on all the time, drop
    # multicast packets unless the packet we expect to see is a multicast
    # packet. For now the only tests that use this are IPv6.
    ipv6 = expected.getlayer("IPv6")
    if ipv6 and ipv6.dst.startswith("ff"):
      include_multicast = True
    else:
      include_multicast = False

    packets = self.ReadAllPacketsOn(netid, include_multicast=include_multicast)
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

  def setUp(self):
    self.ClearTunQueues()

  def tearDown(self):
    # In case there was an exception in one of the tests and we didn't clean up.
    self.BindToDevice(self.listensocket, None)

  def _GetRemoteAddress(self, version):
    return {4: self.IPV4_ADDR, 6: self.IPV6_ADDR}[version]

  def _GetProtocolFamily(self, version):
    return {4: AF_INET, 6: AF_INET6}[version]

  def BuildSocket(self, version, constructor, mark, uid, oif):
    with RunAsUid(uid):
      family = self._GetProtocolFamily(version)
      s = constructor(family)
    if mark:
      self.SetSocketMark(s, mark)
    if oif:
      self.BindToDevice(s, oif)
    return s

  def CheckPingPacket(self, version, mark, uid, oif, dstaddr, packet,
                      expected_netid):
    s = self.BuildSocket(version, net_test.PingSocket, mark, uid, oif)

    myaddr = self.MyAddress(version, expected_netid)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind((myaddr, PING_IDENT))
    net_test.SetSocketTos(s, PING_TOS)

    desc, expected = Packets.ICMPEcho(version, myaddr, dstaddr)

    s.sendto(packet + PING_PAYLOAD, (dstaddr, 19321))
    msg = "IPv%d ping: expected %s on %s" % (
        version, desc, self.GetInterfaceName(expected_netid))
    self.ExpectPacketOn(expected_netid, msg, expected)

  def CheckTCPSYNPacket(self, version, mark, uid, oif, dstaddr, expected_netid):
    s = self.BuildSocket(version, net_test.TCPSocket, mark, uid, oif)

    if version == 6 and dstaddr.startswith("::ffff"):
      version = 4
    myaddr = self.MyAddress(version, expected_netid)
    desc, expected = Packets.SYN(53, version, myaddr, dstaddr,
                                 sport=None, seq=None)

    # Non-blocking TCP connects always return EINPROGRESS.
    self.assertRaisesErrno(errno.EINPROGRESS, s.connect, (dstaddr, 53))
    msg = "IPv%s TCP connect: expected %s on %s" % (
        version, desc, self.GetInterfaceName(expected_netid))
    self.ExpectPacketOn(expected_netid, msg, expected)
    s.close()

  def CheckUDPPacket(self, version, mark, uid, oif, dstaddr, expected_netid):
    s = self.BuildSocket(version, net_test.UDPSocket, mark, uid, oif)

    if version == 6 and dstaddr.startswith("::ffff"):
      version = 4
    myaddr = self.MyAddress(version, expected_netid)
    desc, expected = Packets.UDP(version, myaddr, dstaddr, sport=None)
    msg = "IPv%s UDP %%s: expected %s on %s" % (
        version, desc, self.GetInterfaceName(expected_netid))

    s.sendto(UDP_PAYLOAD, (dstaddr, 53))
    self.ExpectPacketOn(expected_netid, msg % "sendto", expected)

    s.connect((dstaddr, 53))
    s.send(UDP_PAYLOAD)
    self.ExpectPacketOn(expected_netid, msg % "connect/send", expected)
    s.close()

  def CheckOutgoingPackets(self, mode):
    v4addr = self.IPV4_ADDR
    v6addr = self.IPV6_ADDR

    for _ in xrange(self.ITERATIONS):
      for netid in self.tuns:

        if mode == "mark":
          mark, uid, oif = (netid, 0, 0)
        elif mode == "uid":
          mark, uid, oif = (0, self.UidForNetid(netid), 0)
        elif mode == "oif":
          mark, uid, oif = (0, 0, self.GetInterfaceName(netid))
        else:
          raise ValueError("Unkown routing mode %s" % mode)

        self.CheckPingPacket(4, mark, uid, oif, v4addr, self.IPV4_PING, netid)
        # Kernel bug.
        if mode != "oif":
          self.CheckPingPacket(6, mark, uid, oif, v6addr, self.IPV6_PING, netid)

        self.CheckTCPSYNPacket(4, mark, uid, oif, v4addr, netid)
        self.CheckTCPSYNPacket(6, mark, uid, oif, v6addr, netid)
        self.CheckTCPSYNPacket(6, mark, uid, oif, "::ffff:" + v4addr, netid)

        self.CheckUDPPacket(4, mark, uid, oif, v4addr, netid)
        self.CheckUDPPacket(6, mark, uid, oif, v6addr, netid)
        self.CheckUDPPacket(6, mark, uid, oif, "::ffff:" + v4addr, netid)

  def testMarkRouting(self):
    """Checks that socket marking selects the right outgoing interface."""
    self.CheckOutgoingPackets("mark")

  @unittest.skipUnless(HAVE_EXPERIMENTAL_UID_ROUTING, "no UID routing")
  def testUidRouting(self):
    """Checks that UID routing selects the right outgoing interface."""
    self.CheckOutgoingPackets("uid")

  def testOifRouting(self):
    """Checks that oif routing selects the right outgoing interface."""
    self.CheckOutgoingPackets("oif")

  def CheckRemarking(self, version):
    s = net_test.UDPSocket(self._GetProtocolFamily(version))

    # Figure out what packets to expect.
    unspec = {4: "0.0.0.0", 6: "::"}[version]
    sport = Packets.RandomPort()
    s.bind((unspec, sport))
    dstaddr = {4: self.IPV4_ADDR, 6: self.IPV6_ADDR}[version]
    desc, expected = Packets.UDP(version, unspec, dstaddr, sport)

    # For each netid, set that netid's mark on the socket without closing it,
    # and check that the packets sent on that socket go out on the right
    # network.
    for netid in self.tuns:
      self.SetSocketMark(s, netid)
      expected.src = self.MyAddress(version, netid)
      s.sendto("hello", (dstaddr, 53))
      msg = "Remarked UDPv%d socket: expecting %s on %s" % (
          version, desc, self.GetInterfaceName(netid))
      self.ExpectPacketOn(netid, msg, expected)

  def testIPv4Remarking(self):
    """Checks that updating the mark on an IPv4 socket changes routing."""
    self.CheckRemarking(4)

  def testIPv6Remarking(self):
    """Checks that updating the mark on an IPv6 socket changes routing."""
    self.CheckRemarking(6)

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

        # ... with inbound mark sysctl enabled and disabled.
        for sysctl_value in [0, 1]:

          # If we're testing accepting TCP connections, also check that
          # SO_BINDTODEVICE correctly sets the interface the SYN+ACK is sent on.
          # Since SO_BINDTODEVICE and the sysctl do the same thing, it doesn't
          # really make sense to test with sysctl_value=1 and SO_BINDTODEVICE
          # turned on at the same time.
          if mark_behaviour == "accept" and not sysctl_value:
            bind_devices = [None, iif]
          else:
            bind_devices = [None]

          for bound_dev in bind_devices:
            # The socket is unbound in tearDown.
            self.BindToDevice(self.listensocket, bound_dev)

            # Generate the packet here instead of in the outer loop, so
            # subsequent TCP connections use different source ports and
            # retransmissions from old connections don't confuse subsequent
            # tests.
            desc, packet = packet_generator(version, remote_addr, myaddr)
            reply_desc, reply = reply_generator(version, myaddr, remote_addr,
                                                packet)

            msg = "Receiving %s on %s to %s IP, %s=%d, bound_dev=%s" % (
                desc, iif, dest_ip_iface, mark_behaviour, sysctl_value,
                bound_dev)
            sysctl_function(sysctl_value)

            # Cause the kernel to receive packet on iif_netid.
            self.ReceivePacketOn(iif_netid, packet)

            # Expect the kernel to send out reply on the same interface.
            #
            # HACK: IPv6 ping replies always do a routing lookup with the
            # interface the ping came in on. So even if mark reflection is not
            # working, IPv6 ping replies will be properly reflected. Don't
            # fail when that happens.
            if bound_dev or sysctl_value or reply_desc == "ICMPv6 echo reply":
              msg += ": Expecting %s on %s" % (reply_desc, iif)
              reply = self.ExpectPacketOn(iif_netid, msg, reply)
              # If a callback was set, call it.
              if callback:
                callback(sysctl_value, iif_netid, version, myaddr, remote_addr,
                         packet, reply, msg)
            else:
              msg += ": Expecting no packets on %s" % iif
              self.ExpectNoPacketsOn(iif_netid, msg)

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

  def CheckTCPConnection(self, sysctl_value, netid, version,
                         myaddr, remote_addr, packet, reply, msg):
    establishing_ack = Packets.ACK(version, remote_addr, myaddr, reply)[1]
    self.ReceivePacketOn(netid, establishing_ack)
    s, unused_peer = self.listensocket.accept()
    try:
      mark = self.GetSocketMark(s)
    finally:
      s.close()
    if sysctl_value:
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

  @unittest.skipUnless(HAVE_AUTOCONF_TABLE, "no support for per-table autoconf")
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

  @unittest.skipUnless(HAVE_AUTOCONF_TABLE, "our manual routing doesn't do PIO")
  def testOnlinkCommunication(self):
    """Checks that on-link communication goes direct and not through routers."""
    for netid in self.tuns:
      # Send a UDP packet to a random on-link destination.
      s = net_test.UDPSocket(AF_INET6)
      iface = self.GetInterfaceName(netid)
      self.BindToDevice(s, iface)
      # dstaddr can never be our address because GetRandomDestination only fills
      # in the lower 32 bits, but our address has 0xff in the byte before that
      # (since it's constructed from the EUI-64 and so has ff:fe in the middle).
      dstaddr = self.GetRandomDestination(self.IPv6Prefix(netid))
      s.sendto("hello", (dstaddr, 53))

      # Expect an NS for that destination on the interface.
      myaddr = self.MyAddress(6, netid)
      mymac = self.MyMacAddress(netid)
      desc, expected = Packets.NS(myaddr, dstaddr, mymac)
      msg = "Sending UDP packet to on-link destination: expecting %s" % desc
      self.ExpectPacketOn(netid, msg, expected)

      # Send an NA.
      tgtmac = "02:00:00:00:%02x:99" % netid
      _, reply = Packets.NA(dstaddr, myaddr, tgtmac)
      # Don't use ReceivePacketOn, since that uses the router's MAC address as
      # the source. Instead, construct our own Ethernet header with source
      # MAC of tgtmac.
      reply = scapy.Ether(src=tgtmac, dst=mymac) / reply
      self.ReceiveEtherPacketOn(netid, reply)

      # Expect the kernel to send the original UDP packet now that the ND cache
      # entry has been populated.
      sport = s.getsockname()[1]
      desc, expected = Packets.UDP(6, myaddr, dstaddr, sport=sport)
      msg = "After NA response, expecting %s" % desc
      self.ExpectPacketOn(netid, msg, expected)

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


class PMTUTest(MultiNetworkTest):

  IPV6_PATHMTU = 61
  IPV6_DONTFRAG = 62

  def GetSocketMTU(self, s):
    ip6_mtuinfo = s.getsockopt(net_test.SOL_IPV6, self.IPV6_PATHMTU, 32)
    mtu = struct.unpack("=28sI", ip6_mtuinfo)
    return mtu[1]

  def testIPv6PMTU(self):
    for netid in self.tuns:
      s = net_test.Socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
      s.setsockopt(net_test.SOL_IPV6, self.IPV6_DONTFRAG, 1)
      s.setsockopt(net_test.SOL_IPV6, net_test.IPV6_RECVERR, 1)

      srcaddr = self.MyAddress(6, netid)
      dstaddr = self.GetRandomDestination("2001:db8::")
      intermediate = "2001:db8::1"

      self.SetSocketMark(s, netid)  # So the packet has somewhere to go.
      s.connect((dstaddr, 1234))
      self.assertEquals(1500, self.GetSocketMTU(s))

      s.send(1400 * "a")
      packets = self.ReadAllPacketsOn(netid)
      self.assertEquals(1, len(packets))
      toobig = Packets.ICMPPacketTooBig(6, intermediate, srcaddr, packets[0])[1]
      self.ReceivePacketOn(netid, toobig)
      self.assertEquals(1280, self.GetSocketMTU(s))


class UidRoutingTest(net_test.NetworkTest):

  def setUp(self):
    self.iproute = iproute.IPRoute()

  @staticmethod
  def Random():
    return random.randint(100 * 1000, 200 * 1000)

  def GetRules(self, version, priority):
    rules = self.iproute.DumpRules(version)
    out = [(rule, attributes) for rule, attributes in rules
           if attributes.get(iproute.FRA_PRIORITY, 0) == priority]
    return out

  def CheckInitialTablesHaveNoUIDs(self, version):
    rules = []
    for priority in [0, 32766, 32767]:
      rules.extend(self.GetRules(version, priority))
    for _, attributes in rules:
      self.assertNotIn(iproute.EXPERIMENTAL_FRA_UID_START, attributes)
      self.assertNotIn(iproute.EXPERIMENTAL_FRA_UID_END, attributes)

  def testIPv4InitialTablesHaveNoUIDs(self):
    self.CheckInitialTablesHaveNoUIDs(4)

  def testIPv6InitialTablesHaveNoUIDs(self):
    self.CheckInitialTablesHaveNoUIDs(6)

  def CheckGetAndSetRules(self, version):
    priority = self.Random()
    start, end = tuple(sorted([self.Random(), self.Random()]))
    table = self.Random()
    self.iproute.UidRangeRule(version, True, start, end, table,
                              priority=priority)

    try:
      rules = self.GetRules(version, priority)
      self.assertTrue(rules)
      _, attributes = rules[-1]
      self.assertEquals(priority, attributes[iproute.FRA_PRIORITY])
      self.assertEquals(start, attributes[iproute.EXPERIMENTAL_FRA_UID_START])
      self.assertEquals(end, attributes[iproute.EXPERIMENTAL_FRA_UID_END])
      self.assertEquals(table, attributes[iproute.FRA_TABLE])
    finally:
      self.iproute.UidRangeRule(version, False, start, end, table,
                                priority=priority)

  @unittest.skipUnless(HAVE_EXPERIMENTAL_UID_ROUTING, "no UID routing")
  def testIPv4GetAndSetRules(self):
    self.CheckGetAndSetRules(4)

  @unittest.skipUnless(HAVE_EXPERIMENTAL_UID_ROUTING, "no UID routing")
  def testIPv6GetAndSetRules(self):
    self.CheckGetAndSetRules(6)


if __name__ == "__main__":
  unittest.main()
