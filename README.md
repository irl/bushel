bushel
======

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
* [stem](https://stem.torproject.org) 1.7.0+

Test Requirements
-----------------

The tests expect a local directory cache to be running at `127.0.0.1:9030`.
It should be configured with the following `torrc` options:

```
DirPort 9030
UseMicrodescriptors 0
DownloadExtraInfo 1
```
