# Greylost

This sniffs DNS traffic and logs queries. It implements a time-based
filter to narrow the scope of DNS logs for analysts to examine; if
traffic to Google is typical for your environment, you won't be
innundated with these query logs, but WILL get logs for
malwaredomain123.xyz if that is an atypical query.

This can be installed locally, on a resolver/forwarder, or on a
machine plugged into a switchport that is mirroring ports.

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

## Splunk
Add indexes:
```
greylost-all
greylost-misses
greylost-malware
```

Assuming you have Universal Forwarder installed and configured:
```
splunk add monitor /path/to/greylost-all.log -index greylost-all
splunk add monitor /path/to/greylost-misses.log -index greylost-misses
splunk add monitor /path/to/greylost-malware.log -index greylost-malware
```

No dashboards or application exists (yet), but here are some queries
I've found useful:

Search for resolutions of _malware.com_:
```
index=greylost-all "questions{}.qname"="malware.com."
```

Counts of query types. Look out for high number of TXT:
```
index=greylost-misses |chart count by "questions{}.qtype"
```
