import subprocess
import itertools
import csv
import re

CNET_PATH = 'cnet'

seeds = [
  6115639,
  4926537,
  4262856,
  9874520,
  5869596,
  5647578,
  4935074,
  5316812,
  7922423,
  9909705,
]

rates = [
  '10000us',  # 0.01 seconds
  '100000us', # 0.1  seconds
  '250000us', # 0.25 seconds
  '500000us', # 0.5  seconds
  '1s',
  '2s',
  '4s',
  '8s',
  '16s',
]

corruptions = [
  0,
  3,
  6,
  9,
  12,
]

losses = [
  0,
  3,
  6,
  9,
  12,
]

headers = [
  'Simulation time',
  'Events raised',
  'API errors',
  'Messages generated',
  'Messages delivered',
  'Messages incorrect',
  'Message bandwidth',
  'Average delivery time',
  'Frames transmitted',
  'Frames received',
  'Frames corrupted',
  'Frames lost',
  'Frame collisions',
  'Efficiency (bytes AL) / (bytes PL)',
  'Transmission cost',
]

runtime = '300s' # 5 minutes in microseconds

resreg = re.compile("(.*)\s*:\s*(.*)")

template = None
with open('PROJECT_TEMPLATE', 'r') as f:
  template = f.read()
  
with open('out.csv', 'wb') as csvf:
  csv = csv.writer(csvf)
  csv.writerow(headers)

  for seed, rate, corrupt, loss in itertools.product(seeds, rates, corruptions, losses):
    print "Running cnet with s=%d, r=%s, c=%d, l=%d" % (seed, rate, corrupt, loss)

    with open('PROJECT_CURR', 'w') as f:
      out = template.replace('%MESSAGERATE%', rate)
      out = out.replace('%PROBFRAMECORRUPT%', str(corrupt))
      out = out.replace('%PROBFRAMELOSS%', str(loss))
      f.write(out)
    
    res = subprocess.check_output([CNET_PATH, '-z', '-W', '-g', '-S', str(seed), '-e', str(runtime), 'PROJECT_CURR'])
    
    csvline = []
    for line in res.split('\n')[1:16]:
      r = resreg.search(line)
      csvline.append(r.groups()[1])
      
    csv.writerow(csvline)
    