"""
CollecTor Filesystem Protocol.
"""
# TODO: path.join implementation that uses either filesystem or web semantics
import base64
import collections
import datetime
import enum
import functools
import glob
import hashlib
import logging
import os
import os.path

from stem.descriptor import Descriptor
from stem.descriptor import DocumentHandler
from stem.descriptor.extrainfo_descriptor import BridgeExtraInfoDescriptor
from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor
from stem.descriptor.microdescriptor import Microdescriptor
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.descriptor.server_descriptor import BridgeDescriptor
from stem.descriptor.server_descriptor import RelayDescriptor

LOG = logging.getLogger('bushel')

class CollectorInstance(collections.namedtuple("CollectorInstance", ["path", "recent"])):
    """
    A CollecTor instance.
    """
    # TODO: This needs a better docstring.


class CollectorRecentSubdirectory(enum.Enum):
    """
    Enumeration of subdirectory names under the "recent" directory as specified
    in §4.0 of [collector-protocol]_.

    ======================= ===========
    Name                    Description
    ======================= ===========
    BRIDGE_DESCRIPTORS      Bridge descriptors (§4.2)
    EXIT_LISTS              Exit lists (§4.1.1)
    RELAY_DESCRIPTORS       Relay descriptors (§4.3)
    TORPERF                 Torperf and Onionperf (§4.1.2)
    WEBSTATS                Web server access logs (§4.4)
    ======================= ===========
    """
    BRIDGE_DESCRIPTORS = 'bridge-descriptors'
    EXIT_LISTS = 'exit-lists'
    RELAY_DESCRIPTORS = 'relay-descriptors'
    TORPERF = 'torperf'
    WEBSTATS = 'webstats'


class CollectorOutSubdirectory(enum.Enum):
    """
    Enumeration of subdirectory names under the "out" directory as specified in
    §5.0 of [collector-protocol]_.

    ======================= ===========
    Name                    Description
    ======================= ===========
    BRIDGE_DESCRIPTORS      Bridge descriptors (§5.2)
    EXIT_LISTS              Exit lists (§5.1)
    RELAY_DESCRIPTORS       Relay descriptors (§5.3)
    TORPERF                 Torperf and Onionperf (§5.1)
    WEBSTATS                Web server access logs (§5.4)
    ======================= ===========
    """
    BRIDGE_DESCRIPTORS = 'bridge-descriptors'
    EXIT_LISTS = 'exit-lists'
    RELAY_DESCRIPTORS = 'relay-descriptors'
    TORPERF = 'torperf'
    WEBSTATS = 'webstats'


class CollectorOutRelayDescsMarker(enum.Enum):
    """
    Enumeration of marker names under the "relay-descriptors" directory as
    specified in §5.3 of [collector-protocol]_.

    ======================= ===========
    Name                    Description
    ======================= ===========
    CONSENSUS               Network status consensuses (§5.3.2)
    EXTRA_INFO              Relay extra-info descriptors (§5.3.2)
    SERVER_DESCRIPTOR       Relay server descriptors (§5.3.2)
    VOTE                    Network status votes (§5.3.2)
    ======================= ===========
    """
    CONSENSUS = 'consensus'
    EXTRA_INFO = 'extra-info'
    MICRODESC = 'microdesc'
    SERVER_DESCRIPTOR = 'server-descriptor'
    VOTE = 'vote'


class CollectorOutBridgeDescsMarker(enum.Enum):
    """
    Enumeration of marker names under the "bridge-descriptors" directory as
    specified in §5.2 of [collector-protocol]_.

    ======================= ===========
    Name                    Description
    ======================= ===========
    EXTRA_INFO              Bridge extra-info descriptors (§5.2.1)
    SERVER_DESCRIPTOR       Bridge server descriptors (§5.2.1)
    STATUS                  Bridge statuses (§5.2.2)
    ======================= ===========
    """
    EXTRA_INFO = 'extra-info'
    SERVER_DESCRIPTOR = 'server-descriptor'
    STATUSES = 'statuses'


def collector_422_filename(valid_after, fingerprint):
    """
    Create a filename for a bridge status according to §4.2.2 of the
    [collector-protocol]_. For example:

    >>> valid_after = datetime.datetime(2018, 11, 19, 15)
    >>> fingerprint = "BA44A889E64B93FAA2B114E02C2A279A8555C533" # Serge
    >>> collector_422_filename(valid_after, fingerprint)
    '20181119-150000-BA44A889E64B93FAA2B114E02C2A279A8555C533'

    :param ~datetime.datetime valid_after: The valid-after time.
    :param str fingerprint: The fingerprint of the bridge authority.

    :returns: Filename as a :py:class:`str`.
    """
    fingerprint = fingerprint.upper()
    return (f"{valid_after.year}{valid_after.month:02d}"
            f"{valid_after.day:02d}-{valid_after.hour:02d}"
            f"{valid_after.minute:02d}{valid_after.second:02d}"
            f"-{fingerprint}")

def collector_431_filename(valid_after):
    """
    Create a filename for a network status consensus according to §4.3.1 of the
    [collector-protocol]_. For example:

    >>> valid_after = datetime.datetime(2018, 11, 19, 15)
    >>> collector_431_filename(valid_after)
    '2018-11-19-15-00-00-consensus'

    :param ~datetime.datetime valid_after: The valid-after time.

    :returns: Filename as a :py:class:`str`.
    """
    return (f"{valid_after.year}-{valid_after.month:02d}-"
            f"{valid_after.day:02d}-{valid_after.hour:02d}-"
            f"{valid_after.minute:02d}-{valid_after.second:02d}-consensus")


def collector_433_filename(valid_after, v3ident, digest):
    """
    Create a filename for a network status vote according to §4.3.3 of the
    [collector-protocol]_.

    >>> valid_after = datetime.datetime(2018, 11, 19, 15)
    >>> v3ident = "D586D18309DED4CD6D57C18FDB97EFA96D330566"  # moria1
    >>> digest = "663B503182575D242B9D8A67334365FF8ECB53BB"
    >>> collector_433_filename(valid_after, v3ident, digest)  # doctest: +ELLIPSIS
    '2018-11-19-15-00-00-vote-D586D18309DED4CD6D57C18FDB97EFA96D330566-663B...3BB'

    Paths in the Collector File Structure Protocol using this filename expect
    *upper-case* hex-encoded SHA-1 digests.

    >>> v3ident = "d586d18309ded4cd6d57c18fdb97efa96d330566"  # Lower case gets corrected
    >>> digest = "663b503182575d242b9d8a67334365ff8ecb53bb"  # Lower case gets corrected
    >>> collector_433_filename(valid_after, v3ident, digest)  # doctest: +ELLIPSIS
    '2018-11-19-15-00-00-vote-D586D18309DED4CD6D57C18FDB97EFA96D330566-663B...3BB'

    :param ~datetime.datetime valid_after: The valid-after time.
    :param str v3ident: The v3ident of the directory authority.
    :param str digest: The digest of the vote.

    :returns: Filename as a :py:class:`str`.
    """
    v3ident = v3ident.upper()
    digest = digest.upper()
    return (f"{valid_after.year}-{valid_after.month:02d}-"
            f"{valid_after.day:02d}-{valid_after.hour:02d}-"
            f"{valid_after.minute:02d}-{valid_after.second:02d}-vote-"
            f"{v3ident}-{digest}")

def collector_434_filename(valid_after):
    """
    Create a filename for a microdesc-flavoured network status consensus
    according to §4.3.4 of the [collector-protocol]_. For example:

    >>> valid_after = datetime.datetime(2018, 11, 19, 15)
    >>> collector_434_filename(valid_after)
    '2018-11-19-15-00-00-consensus-microdesc'

    :param ~datetime.datetime valid_after: The valid-after time.

    :returns: Filename as a :py:class:`str`.
    """
    return (f"{valid_after.year}-{valid_after.month:02d}-"
            f"{valid_after.day:02d}-{valid_after.hour:02d}-"
            f"{valid_after.minute:02d}-{valid_after.second:02d}-consensus-"
            "microdesc")

def collector_521_substructure(published, digest):
    """
    Create a path substructure according to §5.2.1 of the
    [collector-protocol]_. This is used for server-descriptors and extra-info
    descriptors for both relays and bridges. For example:

    >>> published = datetime.datetime(2018, 11, 19, 9, 17, 56)
    >>> digest = "a94a07b201598d847105ae5fcd5bc3ab10124389"
    >>> collector_521_substructure(published, digest)
    '2018/11/a/9'

    Paths in the Collector File Structure Protocol using this substructure
    expect *lower-case* hex-encoded SHA-1 digests.

    >>> digest = "A94A07B201598D847105AE5FCD5BC3AB10124389" # Upper case gets corrected
    >>> collector_521_substructure(published, digest)
    '2018/11/a/9'

    :param ~datetime.datetime published: The published time.
    :param str digest: The hex-encoded SHA-1 digest for the descriptor. The
                       case will automatically be fixed to lower-case.

    :returns: Path substructure as a :py:class:`str`.
    """
    digest = digest.lower()
    return os.path.join(f"{published.year}", f"{published.month:02d}",
                        f"{digest[0]}", f"{digest[1]}")

def collector_521_path(subdirectory, marker, published, digest):
    """
    Create a path according to §5.2.1 of the [collector-protocol]_. This is
    used for server-descriptors and extra-info descriptors for both relays and
    bridges. For example:

    >>> subdirectory = CollectorOutSubdirectory.RELAY_DESCRIPTORS
    >>> marker = CollectorOutRelayDescsMarker.SERVER_DESCRIPTOR
    >>> published = datetime.datetime(2018, 11, 19, 9, 17, 56)
    >>> digest = "a94a07b201598d847105ae5fcd5bc3ab10124389"
    >>> collector_521_path(subdirectory, marker, published, digest)  # doctest: +ELLIPSIS
    'relay-descriptors/server-descriptor/2018/11/a/9/a94a...389'

    Paths in the Collector File Structure Protocol using this substructure
    expect *lower-case* hex-encoded SHA-1 digests.

    >>> digest = "A94A07B201598D847105AE5FCD5BC3AB10124389" # Upper case gets corrected
    >>> collector_521_path(subdirectory, marker, published, digest)  # doctest: +ELLIPSIS
    'relay-descriptors/server-descriptor/2018/11/a/9/a94a...389'

    :param str subdirectory: The subdirectory under the "out" directory to
                             use. Standard values can be found in
                             :py:data:`CollectorOutSubdirectory`.
    :param str marker: The marker under the subdirectory to use. Standard values
                       can be found in :py:data:`CollectorOutRelayDescsMarker`
                       and :py:data:`CollectorOutBridgeDescsMarker`.
    :param ~datetime.datetime published: The published time.
    :param str digest: The hex-encoded SHA-1 digest for the descriptor. The
                       case will automatically be fixed to lower-case.

    :returns: Path for the descriptor as a :py:class:`str`.
    """
    digest = digest.lower()
    return os.path.join(subdirectory.value, marker.value,
                        collector_521_substructure(published, digest),
                        f"{digest}")

def collector_522_substructure(valid_after):
    """
    Create a path substructure according to §5.2.2 of the
    [collector-protocol]_. This is used for bridge statuses, and network-status
    consensuses and votes. For example:

    >>> valid_after = datetime.datetime(2018, 11, 19, 15)
    >>> collector_522_substructure(valid_after)
    '2018/11/19'

    :param ~datetime.datetime valid_after: The valid-after time.

    :returns: Path substructure as a :py:class:`str`.
    """
    return os.path.join(f"{valid_after.year}", f"{valid_after.month:02d}",
                        f"{valid_after.day:02d}")

def collector_522_path(subdirectory, marker, valid_after, filename):
    """
    Create a path according to §5.2.2 of the [collector-protocol]_. This is
    used for bridge statuses, and network-status consensuses (both ns- and
    microdesc- flavors) and votes. For a bridge status for example:

    >>> subdirectory = CollectorOutSubdirectory.BRIDGE_DESCRIPTORS
    >>> marker = CollectorOutBridgeDescsMarker.STATUSES
    >>> valid_after = datetime.datetime(2018, 11, 19, 15)
    >>> fingerprint = "BA44A889E64B93FAA2B114E02C2A279A8555C533" # Serge
    >>> filename = collector_422_filename(valid_after, fingerprint)
    >>> collector_522_path(subdirectory, marker, valid_after, filename)  # doctest: +ELLIPSIS
    'bridge-descriptors/statuses/2018/11/19/20181119-150000-BA44...533'

    Or alternatively for a network-status consensus:

    >>> subdirectory = CollectorOutSubdirectory.RELAY_DESCRIPTORS
    >>> marker = CollectorOutRelayDescsMarker.CONSENSUS
    >>> valid_after = datetime.datetime(2018, 11, 19, 15)
    >>> filename = collector_431_filename(valid_after)
    >>> collector_522_path(subdirectory, marker, valid_after, filename)
    'relay-descriptors/consensus/2018/11/19/2018-11-19-15-00-00-consensus'

    :param str subdirectory: The subdirectory under the "out" directory to
                             use. Standard values can be found in
                             :py:data:`CollectorOutSubdirectory`.
    :param str marker: The marker under the subdirectory to use. Standard values
                       can be found in :py:data:`CollectorOutRelayDescsMarker`
                       and :py:data:`CollectorOutBridgeDescsMarker`.
    :param ~datetime.datetime valid_after: The valid_after time.
    :param str filename: The filename to use as a :py:class:`str`, typically
                         created with :py:func:`collector_422_filename` for
                         bridge statuses, :py:func:`collector_431_filename` for
                         network-status consensuses, or
                         :py:func:`collector_433_filename` for network-status
                         votes.

    :returns: Path for the descriptor as a :py:class:`str`.
    """
    return os.path.join(subdirectory.value, marker.value,
                        collector_522_substructure(valid_after), filename)

def collector_533_substructure(valid_after):
    """
    Create a substructure according to §5.3.3 of the [collector-protocol]_.
    This is used for microdesc-flavored consensuses and microdescriptors. For
    example:

    >>> valid_after = datetime.datetime(2018, 11, 19, 15)
    >>> collector_533_substructure(valid_after)
    '2018/11'
    """
    return os.path.join(f"{valid_after.year}", f"{valid_after.month:02d}")

def collector_534_consensus_path(valid_after):
    """
    Create a path according to §5.3.4 of the [collector-protocol]_ for a
    **microdesc-flavored** consensus. For example:

    >>> valid_after = datetime.datetime(2018, 11, 19, 15)
    >>> collector_534_consensus_path(valid_after)
    'relay-descriptors/microdesc/2018/11/consensus-microdesc/19/2018-11-19-15-00-00-consensus-microdesc'
    """
    return os.path.join(CollectorOutSubdirectory.RELAY_DESCRIPTORS.value,
                        CollectorOutRelayDescsMarker.MICRODESC.value,
                        collector_533_substructure(valid_after),
                        "consensus-microdesc", f"{valid_after.day:02d}",
                        collector_434_filename(valid_after))

def collector_534_microdescriptor_path(valid_after, digest):
    """
    Create a path according to §5.3.4 of the [collector-protocol]_ for a
    microdescriptor. For example:

    >>> valid_after = datetime.datetime(2018, 11, 19, 15)
    >>> digest = "00d91cf96321fbd536dd07e297a5e1b7e6961ddd10facdd719716e351453168f"
    >>> collector_534_microdescriptor_path(valid_after, digest)
    'relay-descriptors/microdesc/2018/11/micro/0/0/00d91cf96321fbd536dd07e297a5e1b7e6961ddd10facdd719716e351453168f'

    This path in the Collector File Structure Protocol using this substructure
    expect *lower-case* hex-encoded SHA-256 digests.

    >>> valid_after = datetime.datetime(2018, 11, 19, 15)
    >>> digest = "00D91CF96321FBD536DD07E297A5E1B7E6961DDD10FACDD719716E351453168F"
    >>> collector_534_microdescriptor_path(valid_after, digest)
    'relay-descriptors/microdesc/2018/11/micro/0/0/00d91cf96321fbd536dd07e297a5e1b7e6961ddd10facdd719716e351453168f'
    """
    digest = digest.lower()
    return os.path.join(CollectorOutSubdirectory.RELAY_DESCRIPTORS.value,
                        CollectorOutRelayDescsMarker.MICRODESC.value,
                        collector_533_substructure(valid_after), "micro",
                        f"{digest[0]}", f"{digest[1]}", f"{digest}")


COLLECTOR_INSTANCES = [
    CollectorInstance("https://collector.torproject.org/", [
        CollectorRecentSubdirectory.BRIDGE_DESCRIPTORS,
        CollectorRecentSubdirectory.EXIT_LISTS,
        CollectorRecentSubdirectory.RELAY_DESCRIPTORS,
        CollectorRecentSubdirectory.TORPERF,
        CollectorRecentSubdirectory.WEBSTATS,
    ]),
    CollectorInstance("https://collector2.torproject.org/", [
        CollectorRecentSubdirectory.EXIT_LISTS,
        CollectorRecentSubdirectory.RELAY_DESCRIPTORS,
    ]),
]
