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
usage: greylost.py [-h] [--alllog ALLLOG] [--notdnslog NOTDNSLOG]
                   [--greylistmisslog GREYLISTMISSLOG] [-b BPF] [-d]
                   [--learningtime LEARNINGTIME] [--logging] [--ignore IGNORE]
                   [-i INTERFACE] [-o] [-p PRECISION] [-r PIDFILE]
                   [-s FILTERSIZE] [-t FILTERTIME] [-v] [-w DUMPFILE]

greylost by @dmfroberson

optional arguments:
  -h, --help            show this help message and exit
  --alllog ALLLOG       /path/to/all-log -- log of all DNS queries
  --notdnslog NOTDNSLOG
                        /path/to/not-dns-log -- log of non-DNS protocol
                        traffic
  --greylistmisslog GREYLISTMISSLOG
                        /path/to/greylist-miss-log -- log of greylist misses
  -b BPF, --bpf BPF     BPF filter to apply to the sniffer
  -d, --daemonize       Daemonize
  --learningtime LEARNINGTIME
                        Time to baseline queries before alerting on greylist
                        misses
  --logging             Toggle logging
  --ignore IGNORE       File containing list of domains to ignore when
                        greylisting
  -i INTERFACE, --interface INTERFACE
                        Interface to sniff
  -o, --stdout          Toggle stdout output
  -p PRECISION, --precision PRECISION
                        Precision of bloom filter. Ex: 0.001
  -r PIDFILE, --pidfile PIDFILE
                        Path to PID file
  -s FILTERSIZE, --filtersize FILTERSIZE
                        Size of bloom filter
  -t FILTERTIME, --filtertime FILTERTIME
                        Filter time
  -v, --verbose         increase verbosity
  -w DUMPFILE, --dumpfile DUMPFILE
                        Write captured packets to a dumpfile
```

Example:
```
./greylost.py -i eth0 --stdout --logging
```

## Splunk
The JSON logs provided by greylost can be indexed by Splunk.

### Quickstart
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
splunk add monitor /path/to/greylost-notdns.log -index greylost-notdns
```

### Searching
No dashboards or application exists (yet), but here are some queries
I've found useful:

Search for resolutions of _malware.com_:
```
index=greylost-all "questions{}.qname"="malware.com."
```

Counts of queries per host:
```
index=greylost-misses | chart count by saddr
```

Counts of query types:
```
index=greylost-misses |chart count by "questions{}.qtype"
```

Hosts sending non-DNS traffic:
```
index=greylost-notdns | chart count by saddr
```

Hosts querying lots of TXT records:
```
index=greylost-misses "questions{}.qtype"=TXT | chart count by saddr
```