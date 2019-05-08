
import datetime

from nose.tools import assert_equal

from bushel.monitoring import OK, WARNING, CRITICAL, UNKNOWN
from bushel.monitoring import oldest_datetime
from bushel.monitoring import utc_datetime_too_old

def test_oldest_datetime():
    dts = {
        "millenium": datetime.datetime(2000, 1, 1),
        "endoftime": datetime.datetime(2038, 1, 19, 3, 14, 7),
        "64bittime": datetime.datetime(2038, 1, 19, 3, 14, 8),
        "startoftime": datetime.datetime(1970, 1, 1),
        "beforetime": datetime.datetime(1969, 12, 31, 23, 59, 59),
    }
    oldest_key, oldest_dt = oldest_datetime(dts)
    assert_equal(oldest_key, "beforetime")
    assert_equal(oldest_dt, datetime.datetime(1969, 12, 31, 23, 59, 59))

def test_utc_datetime_too_old_ok():
    utcnow = datetime.datetime(2019, 5, 3, 17, 20, 50)
    dts = {
        "ts1": datetime.datetime(2019, 5, 3, 17, 20, 30),
        "ts2": datetime.datetime(2019, 5, 3, 17, 20, 20)
    }
    status, message = utc_datetime_too_old(dts, 60, 120, utcnow=utcnow)
    assert_equal(status, OK)
    assert_equal(message, "Valid response with recent timestamp (30 sec): "
                          "ts2=2019-05-03T17:20:20")

def test_utc_datetime_too_old_warning():
    utcnow = datetime.datetime(2019, 5, 3, 17, 20, 50)
    dts = {
        "ts1": datetime.datetime(2019, 5, 3, 17, 20, 30),
        "ts2": datetime.datetime(2019, 5, 3, 17, 20, 20)
    }
    status, message = utc_datetime_too_old(dts, 25, 35, utcnow=utcnow)
    assert_equal(status, WARNING)
    assert_equal(message, "Timestamp is not recent (30 sec): "
                          "ts2=2019-05-03T17:20:20")

def test_utc_datetime_too_old_critical():
    utcnow = datetime.datetime(2019, 5, 3, 17, 20, 50)
    dts = {
        "ts1": datetime.datetime(2019, 5, 3, 17, 20, 30),
        "ts2": datetime.datetime(2019, 5, 3, 17, 20, 20)
    }
    status, message = utc_datetime_too_old(dts, 15, 25, utcnow=utcnow)
    assert_equal(status, CRITICAL)
    assert_equal(message, "Timestamp is too old (30 sec): "
                          "ts2=2019-05-03T17:20:20")
