#!/usr/bin/python2.5
#
# Copyright 2009 Google Inc. All Rights Reserved.

"""plot_sdcard: A module to plot the results of an sdcard perf test.

Requires Gnuplot python v 1.8

Typical usage:

python
>>> import plot_sdcard as p
>>> (metadata, data) = p.parse('/tmp/data.txt')
>>> p.plotIterations(metadata, data)
>>> p.plotTimes(metadata, data)

"""

#TODO: provide a main so we can pipe the result from the run
#TODO: more comments...

import Gnuplot
from numpy import *
import sys
import re
from itertools import izip

class DataSet(object):
  def __init__(self, line):
    res = re.search('# StopWatch ([\w]+) total/cumulative duration ([0-9.]+)\. Samples: ([0-9]+)', line)
    self.time = []
    self.data = []
    self.name = res.group(1)
    self.duration = float(res.group(2))
    self.iteration = int(res.group(3))
    print "Name: %s Duration: %f Iterations: %d" % (self.name, self.duration, self.iteration)
    self.summary = re.match('([a-z_]+)_total', self.name)

  def __repr__(self):
    return str(zip(self.time, self.data))

  def add(self, time, value):
    self.time.append(time)
    self.data.append(value)

  def rescaleTo(self, length):
    factor = len(self.data) / length

    if factor > 1:
      new_time = []
      new_data = []
      accum = 0.0
      idx = 1
      for t,d in izip(self.time, self.data):
        accum += d
        if idx % factor == 0:
          new_time.append(t)
          new_data.append(accum / factor)
          accum = 0
        idx += 1
      self.time = new_time
      self.data = new_data


class Metadata(object):
  def __init__(self):
    self.kernel = ''
    self.command_line = ''
    self.sched = ''
    self.name = ''
    self.fadvise = ''
    self.iterations = 0
    self.duration = 0.0
    self.complete = False

  def parse(self, line):
    if line.startswith('# Kernel:'):
      self.kernel = re.search('Linux version ([0-9.]+-[0-9]+)', line).group(1)
    elif line.startswith('# Command:'):
      self.command_line = re.search('# Command: [/\w_]+ (.*)', line).group(1)
      self.command_line = self.command_line.replace(' --', '-')
      self.command_line = self.command_line.replace(' -d', '')
      self.command_line = self.command_line.replace('--test=', '')
    elif line.startswith('# Iterations'):
      self.iterations = int(re.search('# Iterations: ([0-9]+)', line).group(1))
    elif line.startswith('# Fadvise'):
      self.fadvise = int(re.search('# Fadvise: ([\w]+)', line).group(1))
    elif line.startswith("# Sched"):
      self.sched = re.search('# Sched features: ([\w]+)', line).group(1)
      self.complete = True

  def asTitle(self):
    return "%s-duration:%f\\n-%s\\n%s" % (self.kernel, self.duration, self.command_line, self.sched)

  def updateWith(self, dataset):
    self.duration = max(self.duration, dataset.duration)
    self.name = dataset.name


def plotIterations(metadata, data):
  gp = Gnuplot.Gnuplot(persist = 1)
  gp('set data style lines')
  gp.clear()
  gp.xlabel("iterations")
  gp.ylabel("duration in second")
  gp.title(metadata.asTitle())
  styles = {}
  line_style = 1

  for dataset in data:
    dataset.rescaleTo(metadata.iterations)
    x = arange(len(dataset.data), dtype='int_')
    if not dataset.name in styles:
      styles[dataset.name] = line_style
      line_style += 1
      d = Gnuplot.Data(x, dataset.data,
                       title=dataset.name,
                       with_='lines ls %d' % styles[dataset.name])
    else: # no need to repeat a title that exists already.
      d = Gnuplot.Data(x, dataset.data,
                       with_='lines ls %d' % styles[dataset.name])

    gp.replot(d)
  gp.hardcopy('/tmp/%s-%s-%f.png' % (metadata.name, metadata.kernel, metadata.duration), terminal='png')

def plotTimes(metadata, data):
  gp = Gnuplot.Gnuplot(persist = 1)
  gp('set data style impulses')
  gp('set xtics 1')
  gp.clear()
  gp.xlabel("seconds")
  gp.ylabel("duration in second")
  gp.title(metadata.asTitle())
  styles = {}
  line_style = 1

  for dataset in data:
    #dataset.rescaleTo(metadata.iterations)
    x = array(dataset.time, dtype='float_')
    if not dataset.name in styles:
      styles[dataset.name] = line_style
      line_style += 1
      d = Gnuplot.Data(x, dataset.data,
                       title=dataset.name,
                       with_='impulses ls %d' % styles[dataset.name])
    else: # no need to repeat a title that exists already.
      d = Gnuplot.Data(x, dataset.data,
                       with_='impulses ls %d' % styles[dataset.name])

    gp.replot(d)
  gp.hardcopy('/tmp/%s-%s-%f.png' % (metadata.name, metadata.kernel, metadata.duration), terminal='png')


def parse(filename):
  f = open(filename, 'r')

  metadata = Metadata()
  data = []  # array of dataset
  dataset = None

  for num, line in enumerate(f):
    try:
      line = line.strip()
      if not line: continue

      if not metadata.complete:
        metadata.parse(line)
        continue

      if re.match('[a-z_]', line):
        continue

      if line.startswith('# StopWatch'): # Start of a new dataset
        if dataset:
          if dataset.summary:
            metadata.updateWith(dataset)
          else:
            data.append(dataset)

        dataset = DataSet(line)
        continue

      if line.startswith('#'):
        continue

      # must be data at this stage
      try:
        (time, value) = line.split(None, 1)
      except ValueError:
        print "skipping line %d: %s" % (num, line)
        continue

      if dataset and not dataset.summary:
        dataset.add(float(time), float(value))

    except Exception, e:
      print "Error parsing line %d" % num, sys.exc_info()[0]
      raise
  data.append(dataset)
  return (metadata, data)
