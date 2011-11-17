#!/usr/bin/env python2
# setup.py: the distutils script to build and install sniffy.
# Copyright Tom Vincent <http://tlvince.com/contact/>

from distutils.core import setup

setup(
    name = 'sniffy',
    scripts = ['sniffy'],
    version = '0.1.0',
    description = 'Sniff video hosting URLs for Flash-free consumption',
    author = 'Tom Vincent',
    author_email = 'http://tlvince.com/contact/',
    url = 'https://github.com/tlvince/sniffy',
    license = 'GPL',
    classifiers = [
        'Programming Language :: Python',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: POSIX :: Linux',
        'Development Status :: 4 - Beta',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Multimedia :: Video :: Display',
        'Topic :: System :: Networking :: Monitoring'
    ]
)
