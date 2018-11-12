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

