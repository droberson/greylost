#!/bin/sh

# greylost-pid-check.sh
# -- respawn greylost if it dies.
# -- meant to be placed in your crontab!
# --
# -- * * * * * /path/to/greylost-pid-check.sh

PIDFILE="/var/run/greylost.pid"
GREYLOST="/path/to/greylost.py -i eth0 -d --logging --pidfile $PIDFILE"


if [ ! -f $PIDFILE ]; then
    echo "greylost not running. Attempting to start."
    $GREYLOST
    exit
else
    kill -0 $(cat $PIDFILE |head -n 1) 2>/dev/null
    if [ $? -eq 0 ]; then
        exit 0
    else
        echo "greylost not running. Attempting to start."
        $GREYLOST
    fi
fi

