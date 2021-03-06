bushel
======

[![Build Status](https://travis-ci.org/irl/bushel.svg?branch=master)](https://travis-ci.org/irl/bushel)

*A bushel of onions is 57 lbs*

**WARNING: bushel is under active development and may look completely different
when you look at it after a few more commits.**

bushel is a command-line client for Tor's directory protocol. It can
recursively download the latest consensus, server descriptors and extra info
descriptors that are available.

It makes use of asyncio internally to manage downloads, with the actual
downloads being performed by stem. stem is also used for parsing descriptors
when they are downloaded.

Requirements
------------

* Python 3.7+ (no really, we're using some new asyncio features)
* [stem](https://stem.torproject.org) 1.8.0+ (master will do for now, because 1.8.0 isn't released)
* [aiofiles](https://github.com/Tinche/aiofiles)
* [nose](https://nose.readthedocs.io/en/latest/)

Getting Started
---------------

On Debian systems:

```
sudo apt install python3.7 python3-virtualenv git
mkdir -p ~/bushel/out
cd ~/bushel
python3.7 -m virtualenv -p /usr/bin/python3.7 .
git clone https://github.com/irl/bushel.git src
. bin/activate
cd src && pip install -r requirements.txt && python setup.py install
cd ~/bushel/out && bushel scrape
```

Unit Tests
----------

Some unit tests expect a local directory cache to be running at
`127.0.0.1:9030`.  It should be configured with the following `torrc` options:

```
DirPort 9030
UseMicrodescriptors 0
DownloadExtraInfo 1
```

If you have not configured this, the tests will not fail, they will just be
skipped. This is not required for normal operation. *We expect this requirement
to go away once we have a mock Directory Server to test against.*

The tests can be run with:

```
python3.7 -m nose --with-doctest
```
