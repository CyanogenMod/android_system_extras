#!/usr/bin/python

"""Partial Python implementation of iproute functionality."""

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

# Data structure formats.
# These aren't constants, they're classes. So, pylint: disable=invalid-name
NLMsgHdr = cstruct.Struct("NLMsgHdr", "=LHHLL", "length type flags seq pid")
NLMsgErr = cstruct.Struct("NLMsgErr", "=i", "error")
NLAttr = cstruct.Struct("NLAttr", "=HH", "nla_len nla_type")


### rtnetlink constants. See include/uapi/linux/rtnetlink.h.
# Message types.
RTM_NEWRULE = 32
RTM_DELRULE = 33
RTM_GETRULE = 34

# Routing message type values (rtm_type).
RTN_UNSPEC = 0
RTN_UNICAST = 1

# Routing protocol values (rtm_protocol).
RTPROT_UNSPEC = 0
RTPROT_STATIC = 4

# Route scope values (rtm_scope).
RT_SCOPE_UNIVERSE = 0

# Named routing tables.
RT_TABLE_UNSPEC = 0

# Data structure formats.
RTMsg = cstruct.Struct(
    "RTMsg", "=BBBBBBBBI",
    "family dst_len src_len tos table protocol scope type flags")


### FIB rule constants. See include/uapi/linux/fib_rules.h.
FRA_PRIORITY = 6
FRA_FWMARK = 10
FRA_TABLE = 15


class IPRoute(object):

  """Provides a tiny subset of iproute functionality."""

  BUFSIZE = 65536

  def _NlAttrU32(self, nla_type, value):
    data = struct.pack("=I", value)
    nla_len = len(data) + len(NLAttr)
    return NLAttr((nla_len, nla_type)).Pack() + data

  def __init__(self):
    # Global sequence number.
    self.seq = 0
    self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                              socket.NETLINK_ROUTE)
    self.sock.connect((0, 0))  # The kernel.
    self.pid = self.sock.getsockname()[1]

  def _Send(self, msg):
    self.seq += 1
    self.sock.send(msg)

  def _Recv(self):
    return self.sock.recv(self.BUFSIZE)

  def _ExpectAck(self):
    # Find the error code.
    response = self._Recv()
    hdr, data = cstruct.Read(response, NLMsgHdr)
    if hdr.type == NLMSG_ERROR:
      error = NLMsgErr(data).error
      if error:
        raise IOError(error, os.strerror(-error))
    else:
      raise ValueError("Unexpected netlink ACK type %d" % hdr.type)

  def _Rule(self, version, is_add, table, match_nlattr, priority):
    """Python equivalent of "ip rule <add|del> <match_cond> lookup <table>".

    Args:
      version: An integer, 4 or 6.
      is_add: True to add a rule, False to delete it.
      table: The table to add/delete the rule from.
      match_nlattr: A blob of struct nlattrs that express the match condition.
      priority: An integer, the priority.

    Raises:
      IOError: If the netlink request returns an error.
      ValueError: If the kernel's response could not be parsed.
    """
    self.seq += 1

    # Create a struct rtmsg specifying the table and the given match attributes.
    family = {4: socket.AF_INET, 6: socket.AF_INET6}[version]
    rtmsg = RTMsg((family, 0, 0, 0, RT_TABLE_UNSPEC,
                   RTPROT_STATIC, RT_SCOPE_UNIVERSE, RTN_UNICAST, 0)).Pack()
    rtmsg += self._NlAttrU32(FRA_PRIORITY, priority)
    rtmsg += match_nlattr
    rtmsg += self._NlAttrU32(FRA_TABLE, table)

    # Create a netlink request containing the rtmsg.
    command = RTM_NEWRULE if is_add else RTM_DELRULE
    flags = NLM_F_REQUEST | NLM_F_ACK
    if is_add:
      flags |= (NLM_F_EXCL | NLM_F_CREATE)

    length = len(NLMsgHdr) + len(rtmsg)
    nlmsg = NLMsgHdr((length, command, flags, self.seq, self.pid)).Pack()

    # Send the message and block forever until we receive a response.
    self._Send(nlmsg + rtmsg)

    # Expect a successful ACK.
    self._ExpectAck()

  def FwmarkRule(self, version, is_add, fwmark, table, priority=16383):
    nlattr = self._NlAttrU32(FRA_FWMARK, fwmark)
    return self._Rule(version, is_add, table, nlattr, priority)

  def DumpRules(self, version):
    """Returns the IP rules for the specified IP version."""
    # Create a struct rtmsg specifying the table and the given match attributes.
    family = {4: socket.AF_INET, 6: socket.AF_INET6}[version]
    rtmsg = RTMsg((family, 0, 0, 0, 0, 0, 0, 0, 0))

    # Create a netlink dump request containing the rtmsg.
    command = RTM_GETRULE
    flags = NLM_F_DUMP | NLM_F_REQUEST
    length = len(NLMsgHdr) + len(rtmsg)
    nlmsghdr = NLMsgHdr((length, command, flags, self.seq, self.pid))

    self._Send(nlmsghdr.Pack() + rtmsg.Pack())
    data = self._Recv()

    rules = []
    while data:
      # Parse the netlink and rtmsg headers.
      nlmsghdr, data = cstruct.Read(data, NLMsgHdr)
      rtmsg, data = cstruct.Read(data, RTMsg)

      # Parse the attributes in the rtmsg.
      attributes = []
      bytesleft = nlmsghdr.length - len(nlmsghdr) - len(rtmsg)
      while bytesleft:
        # Read the nlattr header.
        nla, data = cstruct.Read(data, NLAttr)

        # Read the data. We don't know how to parse attributes, so just return
        # them as raw bytes.
        datalen = nla.nla_len - len(nla)
        nla_data, data = data[:datalen], data[datalen:]

        attributes.append((nla, nla_data))
        bytesleft -= nla.nla_len

      rules.append((rtmsg, attributes))

    return rules
