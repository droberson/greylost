# Greylost
DNS SNIFFING MONKEYSHINES

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

You might have to edit which interface this is sniffing on. I haven't
added CLI handling to specify stuff like this yet... >:|
