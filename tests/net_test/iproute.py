#!/usr/bin/python

"""Partial Python implementation of iproute functionality."""

# pylint: disable=g-bad-todo

import errno
import os
import socket
import struct

import cstruct


### Base netlink constants. See include/uapi/linux/netlink.h.
NETLINK_ROUTE = 0

# Request constants.
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400
NLM_F_DUMP = 0x300

# Message types.
NLMSG_ERROR = 2
NLMSG_DONE = 3

# Data structure formats.
# These aren't constants, they're classes. So, pylint: disable=invalid-name
NLMsgHdr = cstruct.Struct("NLMsgHdr", "=LHHLL", "length type flags seq pid")
NLMsgErr = cstruct.Struct("NLMsgErr", "=i", "error")
NLAttr = cstruct.Struct("NLAttr", "=HH", "nla_len nla_type")

# Alignment / padding.
NLA_ALIGNTO = 4


### rtnetlink constants. See include/uapi/linux/rtnetlink.h.
# Message types.
RTM_NEWADDR = 20
RTM_DELADDR = 21
RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_GETROUTE = 26
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
RTM_NEWRULE = 32
RTM_DELRULE = 33
RTM_GETRULE = 34

# Routing message type values (rtm_type).
RTN_UNSPEC = 0
RTN_UNICAST = 1
RTN_UNREACHABLE = 7

# Routing protocol values (rtm_protocol).
RTPROT_UNSPEC = 0
RTPROT_STATIC = 4

# Route scope values (rtm_scope).
RT_SCOPE_UNIVERSE = 0

# Named routing tables.
RT_TABLE_UNSPEC = 0

# Routing attributes.
RTA_DST = 1
RTA_SRC = 2
RTA_OIF = 4
RTA_GATEWAY = 5
RTA_PRIORITY = 6
RTA_PREFSRC = 7
RTA_TABLE = 15
RTA_MARK = 16
EXPERIMENTAL_RTA_UID = 18

# Data structure formats.
RTMsg = cstruct.Struct(
    "RTMsg", "=BBBBBBBBI",
    "family dst_len src_len tos table protocol scope type flags")


### Interface address constants. See include/uapi/linux/if_addr.h.
# Interface address attributes.
IFA_ADDRESS = 1
IFA_LOCAL = 2

# Address flags.
IFA_F_PERMANENT = 0x80

# Data structure formats.
IfAddrMsg = cstruct.Struct(
    "IfAddrMsg", "=BBBBI",
    "family prefixlen flags scope index")


### Neighbour table entry constants. See include/uapi/linux/neighbour.h.
# Neighbour cache entry attributes.
NDA_DST = 1
NDA_LLADDR = 2

# Neighbour cache entry states.
NUD_PERMANENT = 0x80

# Data structure formats.
NdMsg = cstruct.Struct(
    "NdMsg", "=BxxxiHBB",
    "family ifindex state flags type")


### FIB rule constants. See include/uapi/linux/fib_rules.h.
FRA_PRIORITY = 6
FRA_FWMARK = 10
FRA_TABLE = 15
FRA_OIFNAME = 17
EXPERIMENTAL_FRA_UID_START = 18
EXPERIMENTAL_FRA_UID_END = 19


def CommandVerb(command):
  return ["NEW", "DEL", "GET", "SET"][command % 4]


def CommandSubject(command):
  return ["LINK", "ADDR", "ROUTE", "NEIGH", "RULE"][(command - 16) / 4]


def Decode(command, family, nla_type, nla_data):
  """Decodes netlink attributes to Python types.

  Values for which the code knows the type (e.g., the fwmark ID in a
  RTM_NEWRULE command) are decoded to Python integers, strings, etc. Values
  of unknown type are returned as raw byte strings.

  Args:
    command: An integer, the rtnetlink command being carried out. This is used
      to interpret the attributes. For example, for an RTM_NEWROUTE command,
      attribute type 3 is the incoming interface and is an integer, but for a
      RTM_NEWRULE command, attribute type 3 is the incoming interface name
      and is a string.
    family: The address family. Used to convert IP addresses into strings.
    nla_type: An integer, then netlink attribute type.
    nla_data: A byte string, the netlink attribute data.

  Returns:
    A Python object. (Currently an integer, a string, or a raw byte string.)
  """
  if CommandSubject(command) == "RULE":
    if nla_type in [FRA_PRIORITY, FRA_FWMARK, FRA_TABLE,
                    EXPERIMENTAL_FRA_UID_START, EXPERIMENTAL_FRA_UID_END]:
      return struct.unpack("=I", nla_data)[0]
    elif nla_type in [FRA_OIFNAME]:
      return nla_data.strip("\x00")
  elif CommandSubject(command) == "ROUTE":
    if nla_type in [RTA_DST, RTA_SRC, RTA_GATEWAY, RTA_PREFSRC]:
      return socket.inet_ntop(family, nla_data)
    elif nla_type in [RTA_OIF, RTA_PRIORITY, RTA_TABLE]:
      return struct.unpack("=I", nla_data)[0]

  # Don't know what this is.
  return nla_data


def PaddedLength(length):
  # TODO: This padding is probably overly simplistic.
  return NLA_ALIGNTO * ((length / NLA_ALIGNTO) + (length % NLA_ALIGNTO != 0))


class IPRoute(object):

  """Provides a tiny subset of iproute functionality."""

  BUFSIZE = 65536
  DEBUG = False

  def _Debug(self, s):
    if self.DEBUG:
      print s

  def _NlAttr(self, nla_type, data):
    datalen = len(data)
    # Pad the data if it's not a multiple of NLA_ALIGNTO bytes long.
    padding = "\x00" * (PaddedLength(datalen) - datalen)
    nla_len = datalen + len(NLAttr)
    return NLAttr((nla_len, nla_type)).Pack() + data + padding

  def _NlAttrU32(self, nla_type, value):
    return self._NlAttr(nla_type, struct.pack("=I", value))

  def _NlAttrIPAddress(self, nla_type, family, address):
    return self._NlAttr(nla_type, socket.inet_pton(family, address))

  def _ParseAttributes(self, command, family, data):
    """Parses and decodes netlink attributes.

    Takes a block of NLAttr data structures, decodes them using Decode, and
    returns the result in a dict keyed by attribute number.

    Args:
      command: An integer, the rtnetlink command being carried out.
      family: The address family.
      data: A byte string containing a sequence of NLAttr data structures.

    Returns:
      A dictionary mapping attribute types (integers) to decoded values.

    Raises:
      ValueError: There was a duplicate attribute type.
    """
    attributes = {}
    while data:
      # Read the nlattr header.
      nla, data = cstruct.Read(data, NLAttr)

      # Read the data.
      datalen = nla.nla_len - len(nla)
      padded_len = PaddedLength(nla.nla_len) - len(nla)
      nla_data, data = data[:datalen], data[padded_len:]

      # If it's an attribute we know about, try to decode it.
      nla_data = Decode(command, family, nla.nla_type, nla_data)

      # We only support unique attributes for now.
      if nla.nla_type in attributes:
        raise ValueError("Duplicate attribute %d" % nla.nla_type)

      attributes[nla.nla_type] = nla_data
      self._Debug("      %s" % str((nla, nla_data)))

    return attributes

  def __init__(self):
    # Global sequence number.
    self.seq = 0
    self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                              socket.NETLINK_ROUTE)
    self.sock.connect((0, 0))  # The kernel.
    self.pid = self.sock.getsockname()[1]

  def _Send(self, msg):
    # self._Debug(msg.encode("hex"))
    self.seq += 1
    self.sock.send(msg)

  def _Recv(self):
    data = self.sock.recv(self.BUFSIZE)
    # self._Debug(data.encode("hex"))
    return data

  def _ExpectDone(self):
    response = self._Recv()
    hdr = NLMsgHdr(response)
    if hdr.type != NLMSG_DONE:
      raise ValueError("Expected DONE, got type %d" % hdr.type)

  def _ParseAck(self, response):
    # Find the error code.
    hdr, data = cstruct.Read(response, NLMsgHdr)
    if hdr.type == NLMSG_ERROR:
      error = NLMsgErr(data).error
      if error:
        raise IOError(error, os.strerror(-error))
    else:
      raise ValueError("Expected ACK, got type %d" % hdr.type)

  def _ExpectAck(self):
    response = self._Recv()
    self._ParseAck(response)

  def _AddressFamily(self, version):
    return {4: socket.AF_INET, 6: socket.AF_INET6}[version]

  def _SendNlRequest(self, command, data):
    """Sends a netlink request and expects an ack."""
    flags = NLM_F_REQUEST
    if CommandVerb(command) != "GET":
      flags |= NLM_F_ACK
    if CommandVerb(command) == "NEW":
      flags |= (NLM_F_EXCL | NLM_F_CREATE)

    length = len(NLMsgHdr) + len(data)
    nlmsg = NLMsgHdr((length, command, flags, self.seq, self.pid)).Pack()

    # Send the message.
    self._Send(nlmsg + data)

    if flags & NLM_F_ACK:
      self._ExpectAck()

  def _Rule(self, version, is_add, table, match_nlattr, priority):
    """Python equivalent of "ip rule <add|del> <match_cond> lookup <table>".

    Args:
      version: An integer, 4 or 6.
      is_add: True to add a rule, False to delete it.
      table: If nonzero, rule looks up this table. If 0, it returns ENETUNREACH.
      match_nlattr: A blob of struct nlattrs that express the match condition.
        If None, match everything.
      priority: An integer, the priority.

    Raises:
      IOError: If the netlink request returns an error.
      ValueError: If the kernel's response could not be parsed.
    """
    # Create a struct rtmsg specifying the table and the given match attributes.
    family = self._AddressFamily(version)
    rule_type = RTN_UNICAST if table else RTN_UNREACHABLE
    rtmsg = RTMsg((family, 0, 0, 0, RT_TABLE_UNSPEC,
                   RTPROT_STATIC, RT_SCOPE_UNIVERSE, rule_type, 0)).Pack()
    rtmsg += self._NlAttrU32(FRA_PRIORITY, priority)
    if match_nlattr:
      rtmsg += match_nlattr
    if table:
      rtmsg += self._NlAttrU32(FRA_TABLE, table)

    # Create a netlink request containing the rtmsg.
    command = RTM_NEWRULE if is_add else RTM_DELRULE
    self._SendNlRequest(command, rtmsg)

  def DeleteRulesAtPriority(self, version, priority):
    family = self._AddressFamily(version)
    rtmsg = RTMsg((family, 0, 0, 0, RT_TABLE_UNSPEC,
                   RTPROT_STATIC, RT_SCOPE_UNIVERSE, RTN_UNICAST, 0)).Pack()
    rtmsg += self._NlAttrU32(FRA_PRIORITY, priority)
    while True:
      try:
        self._SendNlRequest(RTM_DELRULE, rtmsg)
      except IOError, e:
        if e.errno == -errno.ENOENT:
          break
        else:
          raise

  def FwmarkRule(self, version, is_add, fwmark, table, priority=16383):
    nlattr = self._NlAttrU32(FRA_FWMARK, fwmark)
    return self._Rule(version, is_add, table, nlattr, priority)

  def OifRule(self, version, is_add, oif, table, priority=16383):
    nlattr = self._NlAttr(FRA_OIFNAME, oif + "\x00")
    return self._Rule(version, is_add, table, nlattr, priority)

  def UidRangeRule(self, version, is_add, start, end, table, priority=16383):
    nlattr = (self._NlAttrU32(EXPERIMENTAL_FRA_UID_START, start) +
              self._NlAttrU32(EXPERIMENTAL_FRA_UID_END, end))
    return self._Rule(version, is_add, table, nlattr, priority)

  def UnreachableRule(self, version, is_add, priority):
    return self._Rule(version, is_add, None, None, priority=priority)

  def _GetRTMsg(self, data):
    """Parses a RTMsg into a header and a dictionary of attributes."""
    # Parse the netlink and rtmsg headers.
    nlmsghdr, data = cstruct.Read(data, NLMsgHdr)
    self._Debug("  %s" % nlmsghdr)

    if nlmsghdr.type == NLMSG_ERROR or nlmsghdr.type == NLMSG_DONE:
      print "done"
      return None, data

    rtmsg, data = cstruct.Read(data, RTMsg)
    self._Debug("    %s" % rtmsg)

    # Parse the attributes in the rtmsg.
    attrlen = nlmsghdr.length - len(nlmsghdr) - len(rtmsg)
    attributes = self._ParseAttributes(nlmsghdr.type, rtmsg.family,
                                       data[:attrlen])
    data = data[attrlen:]
    return (rtmsg, attributes), data

  def _GetRTMsgList(self, data, expect_done):
    out = []
    while data:
      msg, data = self._GetRTMsg(data)
      if msg is None:
        break
      out.append(msg)
    if expect_done:
      self._ExpectDone()
    return out

  def DumpRules(self, version):
    """Returns the IP rules for the specified IP version."""
    # Create a struct rtmsg specifying the table and the given match attributes.
    family = self._AddressFamily(version)
    rtmsg = RTMsg((family, 0, 0, 0, 0, 0, 0, 0, 0))

    # Create a netlink dump request containing the rtmsg.
    command = RTM_GETRULE
    flags = NLM_F_DUMP | NLM_F_REQUEST
    length = len(NLMsgHdr) + len(rtmsg)
    nlmsghdr = NLMsgHdr((length, command, flags, self.seq, self.pid))

    self._Send(nlmsghdr.Pack() + rtmsg.Pack())
    data = self._Recv()
    return self._GetRTMsgList(data, True)

  def _Address(self, version, is_add, addr, prefixlen, flags, scope, ifindex):
    """Adds or deletes an IP address."""
    family = self._AddressFamily(version)
    ifaddrmsg = IfAddrMsg((family, prefixlen, flags, scope, ifindex)).Pack()
    ifaddrmsg += self._NlAttrIPAddress(IFA_ADDRESS, family, addr)
    if version == 4:
      ifaddrmsg += self._NlAttrIPAddress(IFA_LOCAL, family, addr)
    command = RTM_NEWADDR if is_add else RTM_DELADDR
    self._SendNlRequest(command, ifaddrmsg)

  def AddAddress(self, address, prefixlen, ifindex):
    version = 6 if ":" in address else 4
    return self._Address(version, True, address, prefixlen, IFA_F_PERMANENT,
                         RT_SCOPE_UNIVERSE, ifindex)

  def DelAddress(self, address, prefixlen, ifindex):
    version = 6 if ":" in address else 4
    return self._Address(version, False, address, prefixlen, 0, 0, ifindex)

  def _Route(self, version, command, table, dest, prefixlen, nexthop, dev,
             mark, uid):
    """Adds, deletes, or queries a route."""
    family = self._AddressFamily(version)
    rtmsg = RTMsg((family, prefixlen, 0, 0, RT_TABLE_UNSPEC,
                   RTPROT_STATIC, RT_SCOPE_UNIVERSE, RTN_UNICAST, 0)).Pack()
    if command == RTM_NEWROUTE and not table:
      # Don't allow setting routes in table 0, since its behaviour is confusing
      # and differs between IPv4 and IPv6.
      raise ValueError("Cowardly refusing to add a route to table 0")
    if table:
      rtmsg += self._NlAttrU32(FRA_TABLE, table)
    if dest != "default":  # The default is the default route.
      rtmsg += self._NlAttrIPAddress(RTA_DST, family, dest)
    if nexthop:
      rtmsg += self._NlAttrIPAddress(RTA_GATEWAY, family, nexthop)
    if dev:
      rtmsg += self._NlAttrU32(RTA_OIF, dev)
    if mark is not None:
      rtmsg += self._NlAttrU32(RTA_MARK, mark)
    if uid is not None:
      rtmsg += self._NlAttrU32(EXPERIMENTAL_RTA_UID, uid)
    self._SendNlRequest(command, rtmsg)

  def AddRoute(self, version, table, dest, prefixlen, nexthop, dev):
    self._Route(version, RTM_NEWROUTE, table, dest, prefixlen, nexthop, dev,
                None, None)

  def DelRoute(self, version, table, dest, prefixlen, nexthop, dev):
    self._Route(version, RTM_DELROUTE, table, dest, prefixlen, nexthop, dev,
                None, None)

  def GetRoutes(self, dest, oif, mark, uid):
    version = 6 if ":" in dest else 4
    prefixlen = {4: 32, 6: 128}[version]
    self._Route(version, RTM_GETROUTE, 0, dest, prefixlen, None, oif, mark, uid)
    data = self. _Recv()
    # The response will either be an error or a list of routes.
    if NLMsgHdr(data).type == NLMSG_ERROR:
      self._ParseAck(data)
    routes = self._GetRTMsgList(data, False)
    return routes

  def _Neighbour(self, version, is_add, addr, lladdr, dev, state):
    """Adds or deletes a neighbour cache entry."""
    family = self._AddressFamily(version)

    # Convert the link-layer address to a raw byte string.
    if is_add:
      lladdr = lladdr.split(":")
      if len(lladdr) != 6:
        raise ValueError("Invalid lladdr %s" % ":".join(lladdr))
      lladdr = "".join(chr(int(hexbyte, 16)) for hexbyte in lladdr)

    ndmsg = NdMsg((family, dev, state, 0, RTN_UNICAST)).Pack()
    ndmsg += self._NlAttrIPAddress(NDA_DST, family, addr)
    ndmsg += self._NlAttr(NDA_LLADDR, lladdr)
    command = RTM_NEWNEIGH if is_add else RTM_DELNEIGH
    self._SendNlRequest(command, ndmsg)

  def AddNeighbour(self, version, addr, lladdr, dev):
    self._Neighbour(version, True, addr, lladdr, dev, NUD_PERMANENT)

  def DelNeighbour(self, version, addr, lladdr, dev):
    self._Neighbour(version, False, addr, lladdr, dev, 0)


if __name__ == "__main__":
  iproute = IPRoute()
  iproute.DEBUG = True
  iproute.DumpRules(6)
  print iproute.GetRoutes("2001:4860:4860::8888", 0, 0, None)
