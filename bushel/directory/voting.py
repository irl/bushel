"""
An implementation of the voting process used in the Tor directory protocol,
version 3 [dir-spec]_.
"""
import datetime

def valid_after_now_guess():
    """
    Takes a good guess at the valid-after time of the latest consensus. There
    is an assumption that there is a new consensus every hour and that it is
    valid from the top of the hour. Different valid-after times are compliant
    with the protocol however, and so this may be wrong.

    The voting timeline is described in §1.4 of the Tor directory protocol,
    version 3 ([dir-spec]_).

    :returns: The start of the current hour in UTC.
    :rtype: ~datetime.datetime
    """
    # TODO: Support other times to guess from than just "now"
    valid_after = datetime.datetime.utcnow()
    return valid_after.replace(minute=0, second=0)
