#!/usr/bin/env python2
# Copyright 2011 Tom Vincent <http://tlvince.com/contact/>

"""Sniff video hosting URLs for flash-free consumption."""

import pcap
import re
import logging
import os.path
import subprocess
import argparse

def parse_arguments(log_levels):
    """Parse the command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("-l", "--log-level", default="WARN", choices=log_levels,
            help="logging level (default: %(default)s)")
    parser.add_argument("-f", "--log-file", help="logging file name")
    return parser.parse_args()

def handles():
    """Format quvi's supported hosts."""
    # Get all hosts
    hosts = subprocess.check_output(["quvi", "--support"]).split("\n")[:-1]
    # Filter query formats
    hosts = [h.split("\t")[0] for h in hosts]
    # Replace weird sub-strings
    for pattern in [("%", ""), (".w+", ".com")]:
        original, replacement = pattern
        hosts = [h.replace(original, replacement) for h in hosts]
    # XXX: Split related websites
    related = []
    for i in hosts:
        related.extend(i.split("|"))
    return related

def handler(host, path, known_hosts, parser):
    """URL handler."""
    # Ignore root paths
    if len(path) == 1:
        return
    # XXX: can 'in' be greedier?
    if host.startswith("www."):
        host = host[4:]
    if host in known_hosts:
        url = "http://{0}{1}".format(host, path)
        cmd = parser + [url]
        logging.info("loading {0}".format(url))
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def main():
    """Start execution of flashback."""
    log_levels = [k for k in logging.__dict__["_levelNames"].keys() if not
            isinstance(k, int)]

    args = parse_arguments(log_levels)

    logging.basicConfig(level=args.log_level, filename=args.log_file,
        format="{name}: %(levelname)s: %(message)s".format(
            name=os.path.basename(__file__)))

    mplayer = "mplayer -fs -really-quiet"
    quvi = "quvi --quiet --format=best --exec"
    parser = quvi.split(" ")
    parser.append("{0} %u".format(mplayer))

    known_hosts = handles()

    pattern = re.compile("GET (.*) HTTP.*\nHost: ([^\r\n]*)")
    try:
        pc = pcap.pcap(name="eth0", snaplen=1500)
        pc.setfilter("tcp and dst port 80")
        for timestamp, packet in pc:
            regex = pattern.search(packet)
            if regex:
                handler(regex.group(2), regex.group(1), known_hosts, parser)
    except OSError:
        logging.error("must be run as root")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(e)

if __name__ == "__main__":
    main()
