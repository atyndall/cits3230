import subprocess
import itertools
import csv
import re
import multiprocessing
import random
import sys

CNET_PATH = 'cnet'

seeds = [
  569830,
]

rates = [
  '10000us',  # 0.01 seconds
  '100000us', # 0.1  seconds
  '500000us', # 0.5  seconds
]

corruptions = [
  0,
  3,
  12,
]

losses = [
  0,
  3,
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

runtime = '100us'

resreg = re.compile("(.*)\s*:\s*(.*)")

template = None

with open('PROJECT_TEMPLATE', 'r') as f:
  template = f.read()

def check_output(*popenargs, **kwargs):
  r"""Run command with arguments and return its output as a byte string.
 
  Backported from Python 2.7 as it's implemented as pure python on stdlib.
 
  >>> check_output(['/usr/bin/python', '--version'])
  Python 2.6.2
  """
  process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
  output, unused_err = process.communicate()
  retcode = process.poll()
  if retcode:
    cmd = kwargs.get("args")
    if cmd is None:
      cmd = popenargs[0]
    error = subprocess.CalledProcessError(retcode, cmd)
    error.output = output
    raise error
  return output
  
def compute(data):
  global template
  seed, rate, corrupt, loss = data
  print "RUNNING: cnet with s=%d, r=%s, c=%d, l=%d" % (seed, rate, corrupt, loss)
  sys.stdout.flush()

  randname = '%d.project' % random.randint(0, 99999)
  
  with open(randname, 'w') as f:
    out = template.replace('%MESSAGERATE%', rate)
    out = out.replace('%PROBFRAMECORRUPT%', str(corrupt))
    out = out.replace('%PROBFRAMELOSS%', str(loss))
    f.write(out)
  
  try:
    res = check_output([CNET_PATH, '-z', '-W', '-g', '-m', str(60), '-S', str(seed), '-e', str(runtime), randname])
  except subprocess.CalledProcessError as e:
    print "TERMINATED: cnet with s=%d, r=%s, c=%d, l=%d" % (seed, rate, corrupt, loss)
    print e.output
    return []
  
  print "COMPLETE: cnet with s=%d, r=%s, c=%d, l=%d" % (seed, rate, corrupt, loss)
  sys.stdout.flush()
  
  csvline = []
  for line in res.split('\n')[1:16]:
    r = resreg.search(line)
    csvline.append(r.groups()[1])
    
  return csvline
  
with open('out.csv', 'wb') as csvf:
  csv = csv.writer(csvf)
  csv.writerow(headers)
  
  pool = multiprocessing.Pool(10) # Use 10 processes
  
  products = itertools.product(seeds, rates, corruptions, losses)

  for result in pool.imap_unordered(compute, products):
    csv.writerow(result)
    
  pool.terminate()