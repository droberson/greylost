# Greylost

This sniffs DNS traffic and logs queries. It implements a time-based
filter to narrow the scope of DNS logs for analysts to examine; if
traffic to Google is typical for your environment, you won't be
innundated with these query logs, but WILL get logs for
malwaredomain123.xyz if that is an atypical query.

## Installation
```
pip3 install -r requirements.txt
```

## Usage:
```
usage: greylost.py [-h] [-b BPF] [--learningtime LEARNINGTIME] [--logging]
                   [-i INTERFACE] [-o] [-p PRECISION] [-s FILTERSIZE]
                   [-t FILTERTIME]

greylost by @dmfroberson

optional arguments:
  -h, --help            show this help message and exit
  -b BPF, --bpf BPF     BPF filter to apply to the sniffer
  --learningtime LEARNINGTIME
                        Time to baseline queries before alerting on greylist
                        misses
  --logging             Toggle logging
  -i INTERFACE, --interface INTERFACE
                        Interface to sniff
  -o, --stdout          Toggle stdout output
  -p PRECISION, --precision PRECISION
                        Precision of bloom filter. Ex: 0.001
  -s FILTERSIZE, --filtersize FILTERSIZE
                        Size of bloom filter
  -t FILTERTIME, --filtertime FILTERTIME
                        Filter time
```

Example:
```
./greylost.py -i eth0 --stdout --logging
```
