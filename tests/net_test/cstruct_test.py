#!/usr/bin/python
#
# Copyright 2016 The Android Open Source Project
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

import unittest

import cstruct


# These aren't constants, they're classes. So, pylint: disable=invalid-name
TestStructA = cstruct.Struct("TestStructA", "=BI", "byte1 int2")
TestStructB = cstruct.Struct("TestStructB", "=BI", "byte1 int2")


class CstructTest(unittest.TestCase):

  def CheckEquals(self, a, b):
    self.assertEquals(a, b)
    self.assertEquals(b, a)
    assert a == b
    assert b == a
    assert not (a != b)  # pylint: disable=g-comparison-negation,superfluous-parens
    assert not (b != a)  # pylint: disable=g-comparison-negation,superfluous-parens

  def CheckNotEquals(self, a, b):
    self.assertNotEquals(a, b)
    self.assertNotEquals(b, a)
    assert a != b
    assert b != a
    assert not (a == b)  # pylint: disable=g-comparison-negation,superfluous-parens
    assert not (b == a)  # pylint: disable=g-comparison-negation,superfluous-parens

  def testEqAndNe(self):
    a1 = TestStructA((1, 2))
    a2 = TestStructA((2, 3))
    a3 = TestStructA((1, 2))
    b = TestStructB((1, 2))
    self.CheckNotEquals(a1, b)
    self.CheckNotEquals(a2, b)
    self.CheckNotEquals(a1, a2)
    self.CheckNotEquals(a2, a3)
    for i in [a1, a2, a3, b]:
      self.CheckEquals(i, i)
    self.CheckEquals(a1, a3)


if __name__ == "__main__":
  unittest.main()
