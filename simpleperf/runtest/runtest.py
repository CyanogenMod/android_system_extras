#!/usr/bin/env python
#
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Simpleperf runtest runner: run simpleperf runtests on host or on device.

  For a simpleperf runtest like one_function test, it contains following steps:
  1. Run simpleperf record command to record simpleperf_runtest_one_function's
     running samples, which is generated in perf.data.
  2. Run simpleperf report command to parse perf.data, generate perf.report.
  4. Parse perf.report and see if it matches expectation.

  The information of all runtests are stored in runtest.conf.
"""

import re
import subprocess
import xml.etree.ElementTree as ET


class Symbol(object):

  def __init__(self, name, comm, overhead):
    self.name = name
    self.comm = comm
    self.overhead = overhead

  def __str__(self):
    return 'Symbol name=%s comm=%s overhead=%f' % (
        self.name, self.comm, self.overhead)


class SymbolOverheadRequirement(object):

  def __init__(self, symbol_name, comm=None, min_overhead=None,
               max_overhead=None):
    self.symbol_name = symbol_name
    self.comm = comm
    self.min_overhead = min_overhead
    self.max_overhead = max_overhead

  def __str__(self):
    strs = []
    strs.append('SymbolOverheadRequirement symbol_name=%s' %
                self.symbol_name)
    if self.comm is not None:
      strs.append('comm=%s' % self.comm)
    if self.min_overhead is not None:
      strs.append('min_overhead=%f' % self.min_overhead)
    if self.max_overhead is not None:
      strs.append('max_overhead=%f' % self.max_overhead)
    return ' '.join(strs)

  def is_match(self, symbol):
    if symbol.name != self.symbol_name:
      return False
    if self.comm is not None:
      if self.comm != symbol.comm:
        return False
    return True

  def check_matched_symbol(self, symbol):
    if self.min_overhead is not None:
      if self.min_overhead > symbol.overhead:
        return False
    if self.max_overhead is not None:
      if self.max_overhead < symbol.overhead:
        return False
    return True


class Test(object):

  def __init__(self, test_name, executable_name, symbol_overhead_requirements):
    self.test_name = test_name
    self.executable_name = executable_name
    self.symbol_overhead_requirements = symbol_overhead_requirements

  def __str__(self):
    strs = []
    strs.append('Test test_name=%s' % self.test_name)
    strs.append('\texecutable_name=%s' % self.executable_name)
    for symbol_overhead_requirement in self.symbol_overhead_requirements:
      strs.append('\t%s' % symbol_overhead_requirement)
    return '\n'.join(strs)


def load_config_file(config_file):
  tests = []
  tree = ET.parse(config_file)
  root = tree.getroot()
  assert root.tag == 'runtests'
  for test in root:
    assert test.tag == 'test'
    test_name = test.attrib['name']
    executable_name = None
    symbol_overhead_requirements = []
    for test_item in test:
      if test_item.tag == 'executable':
        executable_name = test_item.attrib['name']
      if test_item.tag == 'symbol_overhead':
        for symbol_item in test_item:
          assert symbol_item.tag == 'symbol'
          symbol_name = symbol_item.attrib['name']
          comm = None
          if 'comm' in symbol_item.attrib:
            comm = symbol_item.attrib['comm']
          overhead_min = None
          if 'min' in symbol_item.attrib:
            overhead_min = float(symbol_item.attrib['min'])
          overhead_max = None
          if 'max' in symbol_item.attrib:
            overhead_max = float(symbol_item.attrib['max'])

          symbol_overhead_requirements.append(
              SymbolOverheadRequirement(
                  symbol_name,
                  comm,
                  overhead_min,
                  overhead_max))

    tests.append(
        Test(test_name, executable_name, symbol_overhead_requirements))
  return tests


class Runner(object):

  def __init__(self, perf_path):
    self.perf_path = perf_path

  def record(self, test_executable_name, record_file):
    call_args = [self.perf_path, 'record', '-e',
                 'cpu-cycles:u', '-o', record_file, test_executable_name]
    self._call(call_args)

  def report(self, record_file, report_file):
    call_args = [self.perf_path, 'report', '-i', record_file]
    self._call(call_args, report_file)

  def _call(self, args, output_file=None):
    pass


class HostRunner(Runner):

  """Run perf test on host."""

  def _call(self, args, output_file=None):
    output_fh = None
    if output_file is not None:
      output_fh = open(output_file, 'w')
    subprocess.check_call(args, stdout=output_fh)
    if output_fh is not None:
      output_fh.close()


class DeviceRunner(Runner):

  """Run perf test on device."""

  def _call(self, args, output_file=None):
    output_fh = None
    if output_file is not None:
      output_fh = open(output_file, 'w')
    args_with_adb = ['adb', 'shell']
    args_with_adb.extend(args)
    subprocess.check_call(args_with_adb, stdout=output_fh)
    if output_fh is not None:
      output_fh.close()


class ReportAnalyzer(object):

  """Check if perf.report matches expectation in Configuration."""

  def __read_report_file(self, report_file):
    symbols = []
    report_fh = open(report_file, 'r')
    overhead_start = False
    for line in report_fh:
      line = line.strip()
      if not overhead_start:
        if re.search(r'^Overhead\s+Command.+Symbol$', line):
          overhead_start = True
      else:
        m = re.search(r'^([\d\.]+)%\s+(\S+).*\s+(\S+)$', line)
        if not m:
          continue
        overhead = float(m.group(1))
        comm = m.group(2)
        symbol_name = m.group(3)
        symbols.append(Symbol(symbol_name, comm, overhead))

    report_fh.close()
    return symbols

  def check_symbol_overhead_requirements(self, test, report_file):
    symbols = self.__read_report_file(report_file)

    result = True
    matched = [False] * len(test.symbol_overhead_requirements)
    for symbol in symbols:
      for i in range(len(test.symbol_overhead_requirements)):
        symbol_overhead_requirement = test.symbol_overhead_requirements[i]
        if symbol_overhead_requirement.is_match(symbol):
          matched[i] = True
          fulfilled = symbol_overhead_requirement.check_matched_symbol(symbol)
          if not fulfilled:
            print "Symbol (%s) doesn't match requirement (%s) in test %s" % (
                symbol, symbol_overhead_requirement, test)
            result = False
    for i in range(len(matched)):
      if not matched[i]:
        print 'requirement (%s) has no matched symbol in test %s' % (
            test.symbol_overhead_requirements[i], test)
        result = False
    return result


def main():
  tests = load_config_file('runtest.conf')
  host_runner = HostRunner('simpleperf')
  device_runner = DeviceRunner('simpleperf')
  report_analyzer = ReportAnalyzer()
  for test in tests:
    host_runner.record(test.executable_name, 'perf.data')
    host_runner.report('perf.data', 'perf.report')
    result = report_analyzer.check_symbol_overhead_requirements(
        test, 'perf.report')
    print 'test %s on host %s' % (
        test.test_name, 'Succeeded' if result else 'Failed')
    if not result:
      exit(1)
    device_runner.record(test.executable_name, '/data/perf.data')
    device_runner.report('/data/perf.data', 'perf.report')
    result = report_analyzer.check_symbol_overhead_requirements(
        test, 'perf.report')
    print 'test %s on device %s' % (
        test.test_name, 'Succeeded' if result else 'Failed')
    if not result:
      exit(1)


if __name__ == '__main__':
  main()
