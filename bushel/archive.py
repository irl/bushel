"""
Persistent filesystem-backed archive for Tor directory protocol
descriptors. This is intended to be used as part of an :py:mod:`asyncio`
application. File I/O operations are provided by coroutines and coroutine
methods, with the actual I/O performed in an executor.

.. data:: CollectorOutSubdirectory (enum)

  Subdirectory names under the "out" directory as specified in §5.0 of
  [collector-protocol]_.

  ======================= ===========
  Name                    Description
  ======================= ===========
  BRIDGE_DESCRIPTORS      Bridge descriptors (§5.2)
  EXIT_LISTS              Exit lists (§5.1)
  RELAY_DESCRIPTORS       Relay descriptors (§5.3)
  TORPERF                 Torperf and Onionperf (§5.1)
  WEBSTATS                Web server access logs (§5.4)
  ======================= ===========

.. data:: CollectorOutBridgeDescsMarker (enum)

  Marker names under the "bridge-descriptors" directory as specified in
  §5.2 of [collector-protocol]_.

  ======================= ===========
  Name                    Description
  ======================= ===========
  EXTRA_INFO              Bridge extra-info descriptors (§5.2.1)
  SERVER_DESCRIPTOR       Bridge server descriptors (§5.2.1)
  STATUS                  Bridge statuses (§5.2.2)
  ======================= ===========

.. data:: CollectorOutRelayDescsMarker (enum)

  Marker names under the "relay-descriptors" directory as specified in
  §5.3 of [collector-protocol]_.

  ======================= ===========
  Name                    Description
  ======================= ===========
  CONSENSUS               Network status consensuses (§5.3.2)
  EXTRA_INFO              Relay extra-info descriptors (§5.3.2)
  SERVER_DESCRIPTOR       Relay server descriptors (§5.3.2)
  VOTE                    Network status votes (§5.3.2)
  ======================= ===========
"""
import asyncio
import base64
import datetime
import functools
import glob
import hashlib
import io
import logging
import os
import os.path

import aiofiles

import stem.util.str_tools
from stem.descriptor import Descriptor
from stem.descriptor import DocumentHandler
from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor
from stem.descriptor.extrainfo_descriptor import BridgeExtraInfoDescriptor
from stem.descriptor.microdescriptor import Microdescriptor
from stem.descriptor.server_descriptor import RelayDescriptor
from stem.descriptor.server_descriptor import BridgeDescriptor
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.util import enum

LOG = logging.getLogger('bushel')

CollectorOutSubdirectory = enum.Enum(  # pylint: disable=invalid-name
    ('BRIDGE_DESCRIPTORS', 'bridge-descriptors'),
    ('EXIT_LISTS', 'exit-lists'),
    ('RELAY_DESCRIPTORS', 'relay-descriptors'),
    ('TORPERF', 'torperf'),
    ('WEBSTATS', 'webstats'),
)

CollectorOutRelayDescsMarker = enum.Enum(  # pylint: disable=invalid-name
    ('CONSENSUS', 'consensus'),
    ('EXTRA_INFO', 'extra-info'),
    ('MICRODESC', 'microdesc'),
    ('SERVER_DESCRIPTOR', 'server-descriptor'),
    ('VOTE', 'vote'),
)

CollectorOutBridgeDescsMarker = enum.Enum(  # pylint: disable=invalid-name
    ('EXTRA_INFO', 'extra-info'),
    ('SERVER_DESCRIPTOR', 'server-descriptor'),
    ('STATUSES', 'statuses'),
)


async def parse_file(path, **kwargs):
    """
    Parses a descriptor from a file.

    :param content str/bytes: String to construct the descriptor from
    :param kwargs dict: Additional arguments for
                          :meth:`stem.descriptor.Descriptor.parse_file`.
    :returns: :class:`stem.descriptor.Descriptor` subclass for the given
              content, or a *list* of descriptors if **multiple=True** is
              provided.
    """
    loop = asyncio.get_running_loop()
    try:
        async with aiofiles.open(path, 'rb') as source:
            raw_content = await source.read()
            return await loop.run_in_executor(
                None,
                functools.partial(
                    Descriptor.from_str,
                    raw_content,
                    document_handler=DocumentHandler.DOCUMENT,  # pylint: disable=no-member
                    **kwargs))
    except FileNotFoundError:
        pass
    except StopIteration:
        # TODO: Move the file we tried to open into some area for later
        # inspection so that we can download this again!
        pass


async def aglob(pathname, *, recursive=False):
    """
    :py:mod:`asyncio` wrapper for :py:func:`glob.glob`.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, functools.partial(glob.glob, pathname, recursive=recursive))


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
    return os.path.join(subdirectory, marker,
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
    return os.path.join(subdirectory, marker,
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
    return os.path.join(CollectorOutSubdirectory.RELAY_DESCRIPTORS,
                        CollectorOutRelayDescsMarker.MICRODESC,
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
    return os.path.join(CollectorOutSubdirectory.RELAY_DESCRIPTORS,
                        CollectorOutRelayDescsMarker.MICRODESC,
                        collector_533_substructure(valid_after), "micro",
                        f"{digest[0]}", f"{digest[1]}", f"{digest}")


def prepare_annotated_content(descriptor):
    """
    Encodes annotations and prepends them to the descriptor bytes for writing
    to disk.

    :param ~stem.descriptor.Descriptor descriptor: The descriptor to prepare.

    :returns: :py:class:`bytes` for the annotated descriptor.
    """
    content = descriptor.get_bytes()
    type_annotation = descriptor.type_annotation()
    return str(type_annotation).encode('utf-8') + b"\n" + content


def valid_after_now():
    """
    Takes a good guess at the valid-after time of the latest consensus. There
    is an assumption that there is a new consensus every hour and that it is
    valid from the top of the hour. Different valid-after times are compliant
    with [dir-spec]_ however, and so this may be wrong.

    :returns: A :py:class:`~datetime.datetime` for the top of the hour.
    """
    valid_after = datetime.datetime.utcnow()
    return valid_after.replace(minute=0, second=0)


class DirectoryArchive:
    """
    Persistent filesystem-backed archive for Tor directory protocol
    descriptors.

    This implements the CollecTor File Structure Protocol as detailed in
    [collector-protocol]_.

    :param str archive_path: Either an absolute or relative path to the
                             location of the directory to use for the archive.
                             This location must exist, but may be an empty
                             directory.
    :param bool legacy_archive: If True, disables the use of symlinks for
                                faster descriptor retrieval.
    """

    def __init__(self,
                 archive_path,
                 legacy_archive=False,
                 max_file_concurrency=100):
        self.archive_path = archive_path
        self.legacy_archive = legacy_archive
        self.max_file_concurrency_lock = asyncio.BoundedSemaphore(
            max_file_concurrency)

    ####################
    # out/ Paths       #
    ####################

    def path_for(self, descriptor, create_dir=False):
        """
        The filesystem path that a descriptor will be archived at. These paths
        are defined in [collector-protocol]_.

        It is also possible to set *descriptor* with a :py:class:`str` in
        which case it will be treated as a relative path from the root of the
        archive. For example:

        >>> DirectoryArchive("/srv/archive").path_for("path/to/descriptor")
        '/srv/archive/path/to/descriptor'

        :param bool create_dir: Create the directory ready to archive a
                                descriptor.

        :returns: Archive path for the descriptor as a :py:class:`str`.
        """
        if isinstance(descriptor, str):
            fpath = os.path.join(self.archive_path, descriptor)
        elif isinstance(descriptor, BridgeDescriptor):
            fpath = self.bridge_server_descriptor_path(descriptor.published,
                                                       descriptor.digest())
        elif isinstance(descriptor, BridgeExtraInfoDescriptor):
            fpath = self.bridge_extra_info_descriptor_path(
                descriptor.published, descriptor.digest())
        elif isinstance(descriptor, RelayDescriptor):
            fpath = self.relay_server_descriptor_path(descriptor.published,
                                                      descriptor.digest())
        elif isinstance(descriptor, RelayExtraInfoDescriptor):
            fpath = self.relay_extra_info_descriptor_path(
                descriptor.published, descriptor.digest())
        elif isinstance(descriptor, Microdescriptor):
            # TODO: With better annotations support in stem we can keep the
            # metadata around for the valid_after date.
            fpath = self.relay_microdescriptor_path(valid_after_now(),
                                                    descriptor.digest())
        elif isinstance(descriptor, NetworkStatusDocumentV3) and \
              descriptor.is_consensus:
            if descriptor.is_microdescriptor:
                fpath = self.relay_microdescriptor_consensus_path(
                    descriptor.valid_after)
            else:
                fpath = self.relay_consensus_path(descriptor.valid_after)
        elif isinstance(descriptor, NetworkStatusDocumentV3) and \
              descriptor.is_vote:
            # TODO: The digest functionality should be appearing in stem.
            # https://trac.torproject.org/projects/tor/ticket/28398
            raw_content, ending = str(descriptor), "\ndirectory-signature "
            raw_content = stem.util.str_tools._to_bytes(
                raw_content[:raw_content.find(ending) + len(ending)])
            digest = hashlib.sha1(raw_content).hexdigest().upper()
            fpath = self.relay_vote_path(
                descriptor.valid_after,
                descriptor.directory_authorities[0].v3ident, digest)
        else:
            print(repr(descriptor))
            raise RuntimeError(
                f"Attempted to store unknown descriptor type {type(descriptor)}"
            )
        if create_dir:
            dpath = os.path.dirname(fpath)
            os.makedirs(dpath, exist_ok=True)
        return fpath

    def bridge_server_descriptor_path(self, published, digest):
        """
        Generates a path, including the archive path, for a bridge server
        descriptor with a given published time and digest. For example:

        >>> archive = DirectoryArchive("/srv/archive")
        >>> published = datetime.datetime(2018, 11, 19, 15, 1, 2)
        >>> digest = "a94a07b201598d847105ae5fcd5bc3ab10124389"
        >>> archive.bridge_server_descriptor_path(published, digest)  # doctest: +ELLIPSIS
        '/srv/archive/bridge-descriptors/server-descriptor/2018/11/a/9/a94a...389'

        These paths are defined in §5.2.1 of [collector-protocol]_.

        :param ~datetime.datetime published: The published time of the
                                             descriptor.
        :param str digest: The hex-encoded SHA-1 digest of the descriptor.

        :returns: Archive path as a :py:class:`str`.
        """
        return self.path_for(
            collector_521_path(
                CollectorOutSubdirectory.BRIDGE_DESCRIPTORS,  # pylint: disable=no-member
                CollectorOutRelayDescsMarker.SERVER_DESCRIPTOR,  # pylint: disable=no-member
                published,
                digest))

    def bridge_extra_info_descriptor_path(self, published, digest):
        """
        Generates a path, including the archive path, for a bridge extra-info
        descriptor with a given published time and digest. For example:

        >>> archive = DirectoryArchive("/srv/archive")
        >>> published = datetime.datetime(2018, 11, 19, 9, 17, 56)
        >>> digest = "a94a07b201598d847105ae5fcd5bc3ab10124389"
        >>> archive.bridge_extra_info_descriptor_path(published, digest)  # doctest: +ELLIPSIS
        '/srv/archive/bridge-descriptors/extra-info/2018/11/a/9/a94a...389'

        These paths are defined in §5.2.1 of [collector-protocol]_.

        :param ~datetime.datetime published: The published time of the
                                             descriptor.
        :param str digest: The hex-encoded SHA-1 digest of the descriptor.

        :returns: Archive path as a :py:class:`str`.
        """
        return self.path_for(
            collector_521_path(
                CollectorOutSubdirectory.BRIDGE_DESCRIPTORS,  # pylint: disable=no-member
                CollectorOutRelayDescsMarker.EXTRA_INFO,  # pylint: disable=no-member
                published,
                digest))

    def bridge_status_path(self, valid_after, fingerprint):
        """
        Generates a path, including the archive path, for a bridge status
        valid-after time and generated by the authority with the given
        fingerprint. For example:

        >>> archive = DirectoryArchive("/srv/archive")
        >>> valid_after = datetime.datetime(2018, 11, 19, 15)
        >>> fingerprint = "BA44A889E64B93FAA2B114E02C2A279A8555C533"  # Serge
        >>> archive.bridge_status_path(valid_after, fingerprint)  # doctest: +ELLIPSIS
        '/srv/archive/bridge-descriptors/statuses/2018/11/19/20181119-150000-BA...33'

        These paths are defined in §5.2.2 of [collector-protocol]_.

        :param ~datetime.datetime valid_after: The valid-after time for the
                                               status.
        :param str fingerprint: The fingerprint of the bridge authority.

        :returns: Path as a :py:class:`str`.
        """
        return self.path_for(
            collector_522_path(
                CollectorOutSubdirectory.BRIDGE_DESCRIPTORS,  # pylint: disable=no-member
                CollectorOutBridgeDescsMarker.STATUSES,  # pylint: disable=no-member
                valid_after,
                collector_422_filename(valid_after, fingerprint)))

    def relay_server_descriptor_path(self, published, digest):
        """
        Generates a path, including the archive path, for a relay server
        descriptor with a given published time and digest. For example:

        >>> archive = DirectoryArchive("/srv/archive")
        >>> published = datetime.datetime(2018, 11, 19, 15, 1, 2)
        >>> digest = "a94a07b201598d847105ae5fcd5bc3ab10124389"
        >>> archive.relay_server_descriptor_path(published, digest)  # doctest: +ELLIPSIS
        '/srv/archive/relay-descriptors/server-descriptor/2018/11/a/9/a94a...389'

        These paths are defined in §5.3.2 of [collector-protocol]_.

        :param ~datetime.datetime published: The published time of the
                                             descriptor.
        :param str digest: The hex-encoded SHA-1 digest of the descriptor.

        :returns: Path as a :py:class:`str`.
        """
        return self.path_for(
            collector_521_path(
                CollectorOutSubdirectory.RELAY_DESCRIPTORS,  # pylint: disable=no-member
                CollectorOutRelayDescsMarker.SERVER_DESCRIPTOR,  # pylint: disable=no-member
                published,
                digest))

    def relay_extra_info_descriptor_path(self, published, digest):
        """
        Generates a path, including the archive path, for a relay extra-info
        descriptor with a given published time and digest. For example:

        >>> archive = DirectoryArchive("/srv/archive")
        >>> published = datetime.datetime(2018, 11, 19, 9, 17, 56)
        >>> digest = "a94a07b201598d847105ae5fcd5bc3ab10124389"
        >>> archive.relay_extra_info_descriptor_path(published, digest)  # doctest: +ELLIPSIS
        '/srv/archive/relay-descriptors/extra-info/2018/11/a/9/a94a...389'

        These paths are defined in §5.3.2 of [collector-protocol]_.

        :param ~datetime.datetime published: The published time of the
                                             descriptor.
        :param str digest: The hex-encoded SHA-1 digest of the descriptor.

        :returns: Path as a :py:class:`str`.
        """
        return self.path_for(
            collector_521_path(
                CollectorOutSubdirectory.RELAY_DESCRIPTORS,  # pylint: disable=no-member
                CollectorOutRelayDescsMarker.EXTRA_INFO,  # pylint: disable=no-member
                published,
                digest))

    def relay_microdescriptor_path(self, valid_after, digest):
        digest_bytes = digest.encode('utf-8')
        digest_bytes += b'=' * (len(digest_bytes) % 3)
        digest = base64.decodebytes(digest_bytes).hex()
        return self.path_for(
            collector_534_microdescriptor_path(valid_after, digest))

    def relay_microdescriptor_consensus_path(self, valid_after):
        return self.path_for(collector_534_consensus_path(valid_after))

    def relay_consensus_path(self, valid_after):
        """
        Generates a path, including the archive path, for a network-status
        consensus with a given valid-after time. For example:

        >>> archive = DirectoryArchive("/srv/archive")
        >>> valid_after = datetime.datetime(2018, 11, 19, 15)
        >>> archive.relay_consensus_path(valid_after)
        '/srv/archive/relay-descriptors/consensus/2018/11/19/2018-11-19-15-00-00-consensus'

        These paths are defined in §5.3.2 of [collector-protocol]_.

        :param ~datetime.datetime valid_after: The valid-after time for the
                                               status.
        :param str fingerprint: The fingerprint of the bridge authority.

        :returns: Path as a :py:class:`str`.
        """
        return self.path_for(
            collector_522_path(
                CollectorOutSubdirectory.RELAY_DESCRIPTORS,  # pylint: disable=no-member
                CollectorOutRelayDescsMarker.CONSENSUS,  # pylint: disable=no-member
                valid_after,
                collector_431_filename(valid_after)))

    def relay_vote_path(self, valid_after, v3ident, digest):
        """
        Generates a path, including the archive path, for a network-status vote
        with a given valid-after time, generated by the authority with the
        given v3ident, and with the given digest. For example:

        >>> archive = DirectoryArchive("/srv/archive")
        >>> valid_after = datetime.datetime(2018, 11, 19, 15)
        >>> v3ident = "D586D18309DED4CD6D57C18FDB97EFA96D330566"  # moria1
        >>> digest = "663B503182575D242B9D8A67334365FF8ECB53BB"
        >>> archive.relay_vote_path(valid_after, v3ident, digest)  # doctest: +ELLIPSIS
        '/srv/archive/relay-descriptors/vote/2018/11/19/2018-11-19-15-00-00-vote-D...-...B'

        These paths are defined in §5.3.2 of [collector-protocol]_.

        :param ~datetime.datetime valid_after: The valid-after time.
        :param str v3ident: The v3ident of the directory authority.
        :param str digest: The digest of the vote.

        :returns: Path as a :py:class:`str`.
        """
        return self.path_for(
            collector_522_path(
                CollectorOutSubdirectory.RELAY_DESCRIPTORS,  # pylint: disable=no-member
                CollectorOutRelayDescsMarker.VOTE,  # pylint: disable=no-member
                valid_after,
                collector_433_filename(valid_after, v3ident, digest)))

    ####################
    # Store Descriptor #
    ####################

    async def store(self, descriptor):
        path = self.path_for(descriptor, create_dir=True)
        LOG.info("Saving: %s", path)
        async with self.max_file_concurrency_lock:
            async with aiofiles.open(path, 'wb') as output:
                await output.write(prepare_annotated_content(descriptor))

    ####################
    # Get Descriptor   #
    ####################

    async def relay_server_descriptor(self, digest, published_hint):
        """
        Retrieves a relay's server descriptor from the archive.

        :param str digest: A hex-encoded digest of the descriptor.
        :param ~datetime.datetime published_hint: Provides a hint on the
            published time to allow the descriptor to be found in the archive.
            If the descriptor was not published in the same month as this, it
            will not be found.

        :returns: A :py:class:`stem.descriptor.server_descriptor.RelayDescriptor`
                  if found, otherwise *None*.
        """
        published_hint = published_hint or valid_after_now()
        path = self.relay_server_descriptor_path(published_hint, digest)
        async with self.max_file_concurrency_lock:
            return await parse_file(
                path, descriptor_type="server-descriptor 1.0")

    async def _multiple_descriptors(self, single_descriptor_function, digests,
                                    published_hint):
        return [
            descriptor for descriptor in await asyncio.gather(*[
                single_descriptor_function(digest, published_hint)
                for digest in digests
            ]) if descriptor
        ]

    async def relay_server_descriptors(self, digests, published_hint):
        """
        Retrieves multiple server descriptors published around the same time
        (e.g. all referenced by the same consensus).

        :param list(str) digest: Hex-encoded digests for the descriptors.
        :param ~datetime.datetime published_hint: Provides a hint on the
            published time to allow the descriptor to be found in the archive.
            If the descriptor was not published in the same month as this, it
            will not be found.

        :returns: A :py:class:`list` of
                  :py:class:`stem.descriptor.server_descriptor.RelayDescriptor`.
        """
        return await self._multiple_descriptors(self.relay_server_descriptor,
                                                digests, published_hint)

    async def relay_microdescriptor(self, digest, valid_after_hint):
        """
        Retrieves a relay's microdescriptor from the archive.

        :param str digest: A hex-encoded digest of the descriptor.
        :param ~datetime.datetime valid_after_hint: Provides a hint on the
            valid_after time to allow the descriptor to be found in the archive.
            If the descriptor did not become valid in the same month as this,
            it will not be found.

        :returns: A :py:class:`stem.descriptor.microdescriptor.Microdescriptor`
                  if found, otherwise *None*.
        """
        valid_after_hint = valid_after_hint or valid_after_now()
        path = self.relay_microdescriptor_path(valid_after_hint, digest)
        async with self.max_file_concurrency_lock:
            return await parse_file(
                path, descriptor_type="microdescriptor 1.0")

    async def relay_microdescriptors(self, digests, valid_after_hint):
        """
        Retrieves multiple microdescriptors around the same valid_after time
        (e.g. all referenced by the same microdescriptor consensus).

        :param list(str) digest: Hex-encoded digests for the descriptors.

        :param ~datetime.datetime valid_after_hint: Provides a hint on the
            valid_after time to allow the descriptor to be found in the archive.
            If the descriptor did not become valid in the same month as this,
            it will not be found.

        :returns: A :py:class:`list` of
                  :py:class:`stem.descriptor.microdescriptor.Microdescriptor`.
        """
        return await self._multiple_descriptors(self.relay_microdescriptor,
                                                digests, valid_after_hint)

    async def relay_extra_info_descriptor(self, digest, published_hint):
        """
        Retrieves a relay's extra-info descriptor from the archive.

        :param str digest: A hex-encoded digest of the descriptor.
        :param ~datetime.datetime published_hint: Provides a hint on the
            published time to allow the descriptor to be found in the archive.
            If the descriptor was not published in the same month as this, it
            will not be found.

        :returns: A :py:class:`~stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor`
                  if found, otherwise *None*.
        """
        published_hint = published_hint or valid_after_now()
        path = self.relay_extra_info_descriptor_path(published_hint, digest)
        async with self.max_file_concurrency_lock:
            return await parse_file(path, descriptor_type="extra-info 1.0")

    async def relay_extra_info_descriptors(self, digests, published_hint):
        """
        Retrieves multiple extra-info descriptors published around the same time
        (e.g. all referenced by server-descriptors in the same consensus).

        :param list(str) digest: Hex-encoded digests for the descriptors.
        :param ~datetime.datetime published_hint: Provides a hint on the
            published time to allow the descriptor to be found in the archive.
            If the descriptor was not published in the same month as this, it
            will not be found.

        :returns: A :py:class:`list` of
                  :py:class:`stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor`.
        """
        return await self._multiple_descriptors(
            self.relay_extra_info_descriptor, digests, published_hint)

    async def relay_vote(self, v3ident, digest="*", valid_after=None):
        """
        Retrieves a vote from the archive.

        :param str v3ident: The v3ident of the authority that created the vote.
        :param str digest: A hex-encoded digest of the vote. This will
                           automatically be fixed to upper-case.
        :param ~datetime.datetime valid_after: If set, will retrieve a
            consensus with the given valid_after time, otherwise a vote that
            became valid at the top of the current hour will be retrieved.

        :returns: A :py:class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`
                  if found, otherwise *None*.
        """
        valid_after = valid_after or valid_after_now()
        digest = digest.upper()
        path = self.relay_vote_path(valid_after, v3ident, digest)
        if digest == "*":
            try:
                path = (await aglob(path))[0]
            except IndexError:
                return None
        async with self.max_file_concurrency_lock:
            return await parse_file(
                path, descriptor_type="network-status-vote-3 1.0")

    async def relay_consensus(self, flavor="ns", valid_after=None):
        """
        Retrieves a consensus from the archive.

        :param ~datetime.datetime valid_after: If set, will retrieve a consensus with the
                                     given valid_after time, otherwise a vote
                                     that became valid at the top of the
                                     current hour will be retrieved.

        :returns: A :py:class:`~stem.descriptor.network_status.NetworkStatusDocumentV3`
                  if found, otherwise *None*.
        """
        valid_after = valid_after or valid_after_now()
        if flavor == "microdesc":
            path = self.relay_microdescriptor_consensus_path(valid_after)
        else:  # probably we want "ns"
            path = self.relay_consensus_path(valid_after)
        async with self.max_file_concurrency_lock:
            return await parse_file(path)
