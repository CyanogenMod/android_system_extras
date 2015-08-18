#!/usr/bin/python
import subprocess
import matplotlib.pyplot as plt
import time
import argparse

parser = argparse.ArgumentParser(description="Graph memcpy perf")
parser.add_argument("--files", nargs='+', type=str, help="files to graph", default=None)
args = parser.parse_args()

fig, ax = plt.subplots(nrows=1)
ax.set_xscale('log')

plt.xlabel("size in bytes")
plt.ylabel("BW in GB/s")
plt.title("size vs. bw")
plt.tight_layout()

for arg in args.files:
	f = open(arg)
	size = []
	perf = []
	for line in f:
		# size: 11430912, perf: 6.76051GB/s, iter: 5
		line_split = line.split(",")
		size.append(float(line_split[0].split(":")[1]))
		perf.append(float(line_split[1].split(":")[1].split("G")[0]))

	line, = ax.plot(size, perf, '-',  linewidth=0.2, label=arg)

legend = plt.legend()
plt.show()














