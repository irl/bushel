===============
check_collector
===============

-------------------------------------------------
Check a CollecTor instance for operational issues
-------------------------------------------------
:Manual section: 1

SYNOPSIS
========

  check_collector hostname [module]

DESCRIPTION
===========

Checks a CollecTor instance to ensure that the files it is serving are fresh.

hostname
  The hostname of the CollecTor instance. There are no defaults to avoid
  implicit misconfiguration accidents. Example: "collector.torproject.org".
 
module
  The module to test. If not specified, the script will run through all
  available modules to make sure they are working. When configured for use with
  Nagios or compatible software this should be set to one of: "index",
  "relaydescs", "bridgedescs", "exitlists".

EXAMPLES
========

Run all the checks on the command line to ensure the installation is working
or to perform a one-off test of the Tor Metrics CollecTor instance::

 check_collector collector.torproject.org

Check the Tor Metrics CollecTor instance to see that the relaydescs module has
been running::

 check_collector collector.torproject.org relaydescs


BUGS
====

* bridgedescs module does not check network status document timestamps as the
  timestamp format is different

Please report any bugs found to: https://github.com/irl/bushel/issues.
 
AUTHORS
=======

check_collector is part of bushel, a Python library and application supporting
parts of Tor Metrics.

check_collector and this man page were written by Iain Learmonth
<irl@torproject.org>.

