#!/usr/bin/env python2
# Copyright 2011 Tom Vincent <http://tlvince.com/contact/>

"""Sniff video hosting URLs for flash-free consumption."""

import pcap
import re
import logging

from os.path import basename
from subprocess import Popen, PIPE

def handler(host, path):
    """URL handler."""
    try:
        host.index("youtube.com")
        url = "http://{0}{1}".format(host, path)
        cmd = ["quvi", "--quiet", "--format=best", url, "--exec",
               "mplayer -really-quiet %u"]
        Popen(cmd, stdout=PIPE, stderr=PIPE)
    except ValueError:
        pass

def main():
    """Start execution of flashback."""
    # Setup logging
    logging.basicConfig(format="%(name)s: %(levelname)s: %(message)s")
    logger = logging.getLogger(basename(__file__))

    pattern = re.compile("GET (.*) HTTP.*\nHost: ([^\r\n]*)")
    try:
        pc = pcap.pcap(name="eth0", snaplen=1500)
        pc.setfilter("tcp and dst port 80")
        for timestamp, packet in pc:
            regex = pattern.search(packet)
            if regex:
                handler(regex.group(2), regex.group(1))
    except OSError:
        logger.error("must be run as root")
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
