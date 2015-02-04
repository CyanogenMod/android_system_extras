#!/usr/bin/python

"""Partial Python implementation of iproute functionality."""

import os
import socket
import struct

### Base netlink constants. See include/uapi/linux/netlink.h.
NETLINK_ROUTE = 0

# Request constants.
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400

# Message types.
NLMSG_ERROR = 2

# Data structure formats.
STRUCT_NLMSGHDR = "=LHHLL"
STRUCT_NLMSGERR = "=i"
STRUCT_NLATTR = "=HH"


### rtnetlink constants. See include/uapi/linux/rtnetlink.h.
# Message types.
RTM_NEWRULE = 32
RTM_DELRULE = 33

# Routing message type values (rtm_type).
RTN_UNSPEC = 0
RTN_UNICAST = 1

# Routing protocol values (rtm_protocol).
RTPROT_STATIC = 4

# Route scope values (rtm_scope).
RT_SCOPE_UNIVERSE = 0

# Data structure formats.
STRUCT_RTMSG = "=BBBBBBBBI"


### FIB rule constants. See include/uapi/linux/fib_rules.h.
FRA_FWMARK = 10
FRA_TABLE = 15


def Unpack(fmt, data):
  """Unpacks a data structure with variable-size contents at the end."""
  size = struct.calcsize(fmt)
  data, remainder = data[:size], data[size:]
  return struct.unpack(fmt, data), remainder


class IPRoute(object):

  """Provides a tiny subset of iproute functionality."""

  BUFSIZE = 1024

  def _NlAttrU32(self, nla_type, value):
    data = struct.pack("=I", value)
    nla_len = struct.calcsize(STRUCT_NLATTR) + len(data)
    return struct.pack(STRUCT_NLATTR, nla_len, nla_type) + data

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

  def _Rule(self, version, is_add, table, match_nlattr):
    """Python equivalent of "ip rule <add|del> <match_cond> lookup <table>".

    Args:
      version: An integer, 4 or 6.
      is_add: True to add a rule, False to delete it.
      table: The table to add/delete the rule from.
      match_nlattr: A blob of struct nlattrs that express the match condition.

    Raises:
      IOError: If the netlink request returns an error.
      ValueError: If the kernel's response could not be parsed.
    """
    self.seq += 1

    # Create a struct rtmsg specifying the table and the given match attributes.
    family = {4: socket.AF_INET, 6: socket.AF_INET6}[version]
    rtmsg = struct.pack(STRUCT_RTMSG, family, 0, 0, 0, 0,
                        RTPROT_STATIC, RT_SCOPE_UNIVERSE, RTN_UNICAST, 0)
    rtmsg += match_nlattr
    rtmsg += self._NlAttrU32(FRA_TABLE, table)

    # Create a netlink request containing the rtmsg.
    command = RTM_NEWRULE if is_add else RTM_DELRULE
    flags = NLM_F_REQUEST | NLM_F_ACK
    if is_add:
      flags |= (NLM_F_EXCL | NLM_F_CREATE)

    # Fill in the length field.
    length = struct.calcsize(STRUCT_NLMSGHDR) + len(rtmsg)
    nlmsg = struct.pack(STRUCT_NLMSGHDR, length, command, flags,
                        self.seq, self.pid) + rtmsg

    # Send the message and block forever until we receive a response.
    self._Send(nlmsg)
    response = self._Recv()

    # Find the error code.
    (_, msgtype, _, _, _), msg = Unpack(STRUCT_NLMSGHDR, response)
    if msgtype == NLMSG_ERROR:
      ((error,), _) = Unpack(STRUCT_NLMSGERR, msg)
      if error:
        raise IOError(error, os.strerror(-error))
    else:
      raise ValueError("Unexpected netlink ACK type %d" % msgtype)

  def FwmarkRule(self, version, is_add, fwmark, table):
    nlattr = self._NlAttrU32(FRA_FWMARK, fwmark)
    return self._Rule(version, is_add, table, nlattr)
