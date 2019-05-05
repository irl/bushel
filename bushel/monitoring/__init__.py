"""
Monitoring.

"""

import datetime
import sys
import typing

# Standard Nagios return codes
OK, WARNING, CRITICAL, UNKNOWN = range(4)

NagiosResponseT = typing.Tuple[int, str]

def oldest_datetime(dts: typing.Dict[str, datetime.datetime]) -> typing.Tuple[str, datetime.datetime]:
    oldest_key = min(dts, key=lambda k: dts[k])
    oldest_dt = dts[oldest_key]
    return oldest_key, oldest_dt

def utc_datetime_too_old(dts: typing.Dict[str, datetime.datetime], warning_if_older: int, critical_if_older: int, utcnow: datetime.datetime = None) -> typing.Tuple[int, str]:
    utcnow = utcnow or datetime.datetime.utcnow()
    oldest_key, oldest_dt = oldest_datetime(dts)
    oldest_sec = (utcnow - oldest_dt).total_seconds()
    if oldest_sec > critical_if_older:
        return CRITICAL, "Timestamp is too old (%d sec): %s=%s" % \
                         (oldest_sec, oldest_key, oldest_dt.isoformat(), )
    if oldest_sec > warning_if_older:
        return WARNING, "Timestamp is not recent (%d sec): %s=%s" % \
                         (oldest_sec, oldest_key, oldest_dt.isoformat(), )
    return OK, "Valid response with recent timestamp (%d sec): %s=%s" % \
               (oldest_sec, oldest_key, oldest_dt.isoformat(), )

def nagios_return(status: int, message: str) -> None:
    if status == OK:
        print("OK: %s" % message)
    elif status == WARNING:
        print("WARNING: %s" % message)
    elif status == CRITICAL:
        print("CRITICAL: %s" % message)
    else:
        print("UNKNOWN: %s" % message)
        status = UNKNOWN
    sys.exit(status)

def nagios_wrapper(check_function: typing.Callable[[], typing.Tuple[int, str]]) -> None:
    try:
        status, message = check_function()
    except KeyboardInterrupt:
        status, message = CRITICAL, "Caught Control-C..."
    except Exception as e:
        status = CRITICAL
        message = repr(e)
    finally:
        nagios_return(status, message)

def nagios_check(check_function: typing.Callable[[], NagiosResponseT]) -> typing.Callable[[], None]:
    def wrapped_check():
        return nagios_wrapper(check_function)
    return wrapped_check