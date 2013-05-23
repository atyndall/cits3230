import subprocess
import itertools
import csv
import re
import multiprocessing
import random
import sys
import time

## START CONFIG

# Path to cnet executable
CNET_PATH = 'cnet'

# Number of different cnets to run simultaneously
# Don't pick a higher number than cores you have, unless you want to cry
PROCESSES = 10

# Random number seeds to test
seeds = [
  569830,
]

# Message rates to test
rates = [
  '100000us', # 0.1  seconds
  '300000us', # 0.3  seconds
  '1000000us', # 1  seconds
]

# Corruption rates to test
corruptions = [
  0,
  3,
]

# Loss rates to test
losses = [
  0,
  3,
]

# Simulation runtime
runtime = '12s'

# Maximum wall-clock runtime
max_minutes = 60 * 24 # 24 hours

## END CONFIG

headers = [
  'seed', 'rate', 'corrupt', 'loss', 'execstatus', 'execout', 'exectime',
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
  i, data2 = data
  seed, rate, corrupt, loss = data2
  time.sleep(i*2) # Hopefully avoid startup collisions now
  print "RUNNING: cnet %d with s=%d, r=%s, c=%d, l=%d" % (i, seed, rate, corrupt, loss)
  sys.stdout.flush()

  randname = '%d.project' % random.randint(0, 99999)
  
  with open(randname, 'w') as f:
    out = template.replace('%MESSAGERATE%', rate)
    out = out.replace('%PROBFRAMECORRUPT%', str(corrupt))
    out = out.replace('%PROBFRAMELOSS%', str(loss))
    f.write(out)
  
  start_time = time.time()
  try:
    params = [CNET_PATH, '-z', '-W', '-g', '-q', '-m', str(max_minutes), '-S', str(seed), '-e', str(runtime), randname]
    print ' '.join(params)
    res = check_output(params)
  except subprocess.CalledProcessError as e:
    print "TERMINATED: cnet %d with s=%d, r=%s, c=%d, l=%d" % (i, seed, rate, corrupt, loss)
    print e.output
    sys.stdout.flush()
    end_time = time.time()
    return [seed, rate, corrupt, loss, 'failure', e.output, (end_time - start_time)]
    
  end_time = time.time()
  print "COMPLETE: cnet %d with s=%d, r=%s, c=%d, l=%d" % (i, seed, rate, corrupt, loss)
  sys.stdout.flush()
  
  csvline = [seed, rate, corrupt, loss, 'success', res, (end_time - start_time)]
  
  for line in res.split('\n')[1:16]:
    r = resreg.search(line)
    csvline.append(r.groups()[1])
    
  return csvline
  
with open('out.csv', 'wb') as csvf:
  csv = csv.writer(csvf)
  csv.writerow(headers)
  csvf.flush()
  
  pool = multiprocessing.Pool(PROCESSES)
  
  products = itertools.product(seeds, rates, corruptions, losses)

  for result in pool.imap_unordered(compute, enumerate(products)):
    csv.writerow(result)
    csvf.flush()
    
  pool.terminate()
