"""
Persistent filesystem-backed archive for Tor directory protocol
descriptors.

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

.. data:: CollectorOutBridgeDescsMarker (enum)

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
from stem.descriptor import parse_file as stem_parse_file
from stem.descriptor import DocumentHandler
from stem.descriptor.server_descriptor import RelayDescriptor
from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.util import enum

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR

LOG = logging.getLogger('')

CollectorOutSubdirectory = enum.Enum(
    ('BRIDGE_DESCRIPTORS', 'bridge-descriptors'),
    ('EXIT_LISTS', 'exit-lists'),
    ('RELAY_DESCRIPTORS', 'relay-descriptors'),
    ('TORPERF', 'torperf'),
    ('WEBSTATS', 'webstats'),
)

CollectorOutRelayDescsMarker = enum.Enum(
    ('CONSENSUS', 'consensus'),
    ('EXTRA_INFO', 'extra-info'),
    ('SERVER_DESCRIPTOR', 'server-descriptor'),
    ('VOTE', 'vote'),
)

CollectorOutBridgeDescsMarker = enum.Enum(
    ('EXTRA_INFO', 'extra-info'),
    ('SERVER_DESCRIPTOR', 'server-descriptor'),
    ('STATUSES', 'statuses'),
)


async def parse_file(path, **kwargs):
    loop = asyncio.get_running_loop()
    try:
        async with aiofiles.open(path, 'rb') as source:
            raw_content = await source.read()
            return next(await loop.run_in_executor(
                None,
                functools.partial(
                    stem_parse_file,
                    io.BytesIO(raw_content),
                    document_handler=DocumentHandler.DOCUMENT,  # pylint: disable=no-member
                    **kwargs)))
    except FileNotFoundError:
        pass
    except StopIteration:
        # TODO: Move the file we tried to open into some area for later
        # inspection so that we can download this again!
        pass


async def aglob(pathname, recursive=False):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, functools.partial(glob.glob, pathname, recursive=recursive))


def collector_422_filename(valid_after, fingerprint):
    """
    Create a filename for a bridge status according to §4.2.2 of the
    [collector-protocol]_.

    :param datetime.datetime valid_after: The valid-after time.
    :param str fingerprint: The fingerprint of the bridge authority.

    :returns: The filename as a *str*.
    """
    return (f"{valid_after.year}{valid_after.month:02d}"
            f"{valid_after.day:02d}-{valid_after.hour:02d}"
            f"{valid_after.minute:02d}{valid_after.second:02d}"
            f"-{fingerprint}")


def collector_431_filename(valid_after):
    """
    Create a filename for a network status consensus according to §4.3.1 of the
    [collector-protocol]_.

    :param datetime.datetime valid_after: The valid-after time.

    :returns: The filename as a *str*.
    """
    return (f"{valid_after.year}-{valid_after.month:02d}-"
            f"{valid_after.day:02d}-{valid_after.hour:02d}-"
            f"{valid_after.minute:02d}-{valid_after.second:02d}-consensus")


def collector_433_filename(valid_after, v3ident, digest):
    """
    Create a filename for a network status vote according to §4.3.3 of the
    [collector-protocol]_.

    .. warning:: Paths in the Collector File Structure Protocol using this
                 filename expect *upper-case* hex-encoded SHA-1 digests.

    :param datetime.datetime valid_after: The valid-after time.
    :param str v3ident: The v3ident of the directory authority.
    :param str digest: The digest of the vote.

    :returns: The filename as a *str*.
    """
    return (f"{valid_after.year}-{valid_after.month:02d}-"
            f"{valid_after.day:02d}-{valid_after.hour:02d}-"
            f"{valid_after.minute:02d}-{valid_after.second:02d}-vote-"
            f"{v3ident}-{digest}")


def collector_521_substructure(published, digest):
    """
    Create a path substructure according to §5.2.1 of the
    [collector-protocol]_. This is used for server-descriptors and extra-info
    descriptors for both relays and bridges.

    .. warning:: Paths in the Collector File Structure Protocol using this
                 substructure expect *lower-case* hex-encoded SHA-1 digests.

    :param datetime.datetime published: The published time.
    :param str digest: The hex-encoded SHA-1 digest for the descriptor. The
                       case will automatically be fixed to lower-case.

    :returns: The path substructure as a *str*.
    """
    digest = digest.lower()
    return os.path.join(f"{published.year}", f"{published.month:02d}",
                        f"{digest[0]}", f"{digest[1]}")


def collector_522_substructure(valid_after):
    """
    Create a path substructure according to §5.2.2 of the
    [collector-protocol]_. This is used for bridge statuses, and network-status
    consensuses and votes.

    :param datetime.datetime valid_after: The valid-after time.

    :returns: The path substructure as a *str*.
    """
    return os.path.join(f"{valid_after.year}", f"{valid_after.month:02d}",
                        f"{valid_after.day:02d}")


def _type_annotation_for(descriptor):
    # This functionality is now implemented in stem, just keeping it around
    # here until it lands in a release.
    # https://trac.torproject.org/projects/tor/ticket/28397
    annotations = {
        RelayDescriptor: b"server-descriptor 1.0",
        RelayExtraInfoDescriptor: b"extra-info 1.0",
    }
    # stem uses the same class for both consensus and votes so we need
    # to have special logic for that
    if isinstance(descriptor, NetworkStatusDocumentV3):
        if descriptor.is_consensus:
            return b"network-status-consensus-3 1.0"
        if descriptor.is_vote:
            return b"network-status-vote-3 1.0"
        raise RuntimeError(
            "It's a network status but not a consensus or vote?")
    return annotations.get(type(descriptor), None)


def prepare_annotated_content(descriptor):
    content = descriptor.get_bytes()
    type_annotation = _type_annotation_for(descriptor)
    if type_annotation is not None:
        return b"@type " + type_annotation + b"\r\n" + content
    return content


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

    This implements a superset of the CollecTor filesystem protocol as
    detailed in [collector-protocol]_. The additional functionality is used
    to allow quick retrieval of descriptors by their digest by creating a
    parallel directory hierachy containing symlinks. The assumption is that
    the filesystem has better data structures for traversing a hash tree than
    can be hacked on in the time available for this prototype. This extra
    functionality may disappear in later versions.

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
                 max_file_concurrency=200):
        self.archive_path = archive_path
        self.legacy_archive = legacy_archive
        self.max_file_concurrency_lock = asyncio.BoundedSemaphore(
            max_file_concurrency)

    ####################
    # Non-standard     #
    ####################

    #def digest_path_for(self, descriptor, algo="sha1", create_dir=False):
    #    if self.legacy_archive:
    #        raise RuntimeError("Cannot get a digest path for descriptors in a "
    #                           "legacy archive.")
    #    if algo == "sha1":
    #        digest = descriptor.digest()
    #    else:
    #        raise RuntimeError(
    #            "Unknown digest algorithm requested for symlink path")
    #    if isinstance(descriptor, RelayDescriptor):
    #        dpath, fpath = self._descriptor_digest_path(
    #            SERVER_DESCRIPTOR_MARKER, algo, digest)
    #    elif isinstance(descriptor, RelayExtraInfoDescriptor):
    #        dpath, fpath = self._descriptor_digest_path(
    #            EXTRA_INFO_DESCRIPTOR_MARKER, algo, digest)
    #    elif isinstance(descriptor, NetworkStatusDocumentV3) \
    #          and descriptor.is_consensus:
    #        dpath, fpath = "/tmp", "/tmp/consensus"
    #    else:
    #        print(repr(descriptor))
    #        raise RuntimeError(
    #            f"Attempted to store unknown descriptor type {type(descriptor)}"
    #        )
    #    if create_dir:
    #        os.makedirs(dpath, exist_ok=True)
    #    return fpath

    #def _descriptor_digest_path(self, marker, algo, digest):
    #    digest = digest.lower()
    #    dpath = os.path.join(self.archive_path, "relay-descriptors",
    #                         f"{marker}", f"by-{algo}",
    #                         *[f"{digest[i]}" for i in range(0, 10)])
    #    fpath = os.path.join(dpath, f"{digest}")
    #    return dpath, fpath

    ####################
    # §5.0             #
    ####################

    def path_for(self, descriptor, create_dir=False):
        """
        The filesystem path that a descriptor will be archived at. These paths
        are defined in [collector-protocol]_.

        :param bool create_dir: Create the directory ready to archive a
                                descriptor.

        :returns: Archive path for the descriptor as a :py:class:`str`.
        """
        if isinstance(descriptor, RelayDescriptor):
            dpath, fpath = self.relay_server_descriptor_path(
                descriptor.published, descriptor.digest())
        elif isinstance(descriptor, RelayExtraInfoDescriptor):
            dpath, fpath = self.relay_extra_info_descriptor_path(
                descriptor.published, descriptor.digest())
        elif isinstance(descriptor, NetworkStatusDocumentV3) and \
              descriptor.is_consensus:
            dpath, fpath = self.relay_consensus_path(descriptor.valid_after)
        elif isinstance(descriptor, NetworkStatusDocumentV3) and \
              descriptor.is_vote:
            # TODO: The digest functionality should be appearing in stem.
            # https://trac.torproject.org/projects/tor/ticket/28398
            raw_content, ending = str(descriptor), "\ndirectory-signature "
            raw_content = stem.util.str_tools._to_bytes(
                raw_content[:raw_content.find(ending) + len(ending)])
            digest = hashlib.sha1(raw_content).hexdigest().upper()
            dpath, fpath = self.relay_vote_path(
                descriptor.valid_after,
                descriptor.directory_authorities[0].v3ident, digest)
        else:
            print(repr(descriptor))
            raise RuntimeError(
                f"Attempted to store unknown descriptor type {type(descriptor)}"
            )
        if create_dir:
            os.makedirs(dpath, exist_ok=True)
        return fpath

    ####################
    # §5.2.1           #
    ####################

    def collector_521_path(self, subdirectory, marker, published, digest):
        digest = digest.lower()
        dpath = os.path.join(self.archive_path, subdirectory, marker,
                             collector_521_substructure(published, digest))
        fpath = os.path.join(dpath, f"{digest}")
        return dpath, fpath

    def bridge_server_descriptor_path(self, published, digest):
        return self.collector_521_path(
            CollectorOutSubdirectory.BRIDGE_DESCRIPTORS,
            CollectorOutRelayDescsMarker.SERVER_DESCRIPTOR, published, digest)

    def bridge_extra_info_descriptor_path(self, published, digest):
        return self.collector_521_path(
            CollectorOutSubdirectory.BRIDGE_DESCRIPTORS,
            CollectorOutRelayDescsMarker.EXTRA_INFO, published, digest)

    ####################
    # §5.2.2           #
    ####################

    def collector_522_path(self, subdirectory, marker, valid_after, filename):
        dpath = os.path.join(self.archive_path, subdirectory, marker,
                             collector_522_substructure(valid_after))
        fpath = os.path.join(dpath, filename)
        return dpath, fpath

    def bridge_status_path(self, valid_after, fingerprint):
        return self.collector_522_path(
            CollectorOutSubdirectory.BRIDGE_DESCRIPTORS,
            CollectorOutBridgeDescsMarker.STATUSES, valid_after,
            collector_422_filename(valid_after, fingerprint))

    ####################
    # §5.3.2           #
    ####################

    def relay_server_descriptor_path(self, published, digest):
        return self.collector_521_path(
            CollectorOutSubdirectory.RELAY_DESCRIPTORS,
            CollectorOutRelayDescsMarker.SERVER_DESCRIPTOR, published, digest)

    def relay_extra_info_descriptor_path(self, published, digest):
        return self.collector_521_path(
            CollectorOutSubdirectory.RELAY_DESCRIPTORS,
            CollectorOutRelayDescsMarker.EXTRA_INFO, published, digest)

    def relay_consensus_path(self, valid_after):
        return self.collector_522_path(
            CollectorOutSubdirectory.RELAY_DESCRIPTORS,
            CollectorOutRelayDescsMarker.CONSENSUS, valid_after,
            collector_431_filename(valid_after))

    def relay_vote_path(self, valid_after, v3ident, digest):
        return self.collector_522_path(
            CollectorOutSubdirectory.RELAY_DESCRIPTORS,
            CollectorOutRelayDescsMarker.VOTE, valid_after,
            collector_433_filename(valid_after, v3ident, digest))

    ####################
    # Store Descriptor #
    ####################

    async def store(self, descriptor):
        path = self.path_for(descriptor, create_dir=True)
        async with self.max_file_concurrency_lock:
            async with aiofiles.open(path, 'wb') as output:
                await output.write(prepare_annotated_content(descriptor))
            if not isinstance(descriptor, NetworkStatusDocumentV3):
                pass
                # TODO: Create symlinks for descriptors too
                #digest_path = self.digest_path_for(
                #    descriptor, "sha1", create_dir=True)
                # TODO: Make the symlink async
                #os.symlink(os.path.abspath(path), digest_path)

    ####################
    # Get Descriptor   #
    ####################

    async def relay_server_descriptor(self, digest, published_hint):
        published_hint = published_hint or valid_after_now()
        _, path = self.relay_server_descriptor_path(published_hint, digest)
        async with self.max_file_concurrency_lock:
            return await parse_file(
                path, descriptor_type="server-descriptor 1.0")

    async def relay_extra_info_descriptor(self, digest, published_hint):
        published_hint = published_hint or valid_after_now()
        _, path = self.relay_extra_info_descriptor_path(published_hint, digest)
        async with self.max_file_concurrency_lock:
            return await parse_file(path, descriptor_type="extra-info 1.0")

    async def vote(self, v3ident, digest="*", valid_after=None):
        """
        Retrieves a vote from the archive.

        :param str v3ident: The v3ident of the authority that created the vote.
        :param str digest: A hex-encoded digest of the vote. If set to "*" then
                           a vote, but only one vote, will be returned if any
                           vote is available for the given v3ident and
                           valid_after time.
        :param datetime valid_after: If set, will retrieve a consensus with the
                                     given valid_after time, otherwise a
                                     vote that became valid at the top
                                     of the current hour will be retrieved.
        """
        valid_after = valid_after or valid_after_now()
        _, path = self.relay_vote_path(valid_after, v3ident, digest)
        if digest == "*":
            try:
                path = (await aglob(path))[0]
            except IndexError:
                return None
        async with self.max_file_concurrency_lock:
            return await parse_file(
                path, descriptor_type="network-status-vote-3 1.0")

    async def consensus(self, valid_after=None):
        """
        Retrieves a consensus from the archive.

        :param datetime valid_after: If set, will retrieve a consensus with the
                                     given valid_after time, otherwise a vote
                                     that became valid at the top of the
                                     current hour will be retrieved.

        :returns: A :py:class:`~stem.descriptor.network_status.NetworkStatusDocumentV3`
                  if found, otherwise *None*.
        """
        valid_after = valid_after or valid_after_now()
        _, path = self.relay_consensus_path(valid_after)
        print(path)
        async with self.max_file_concurrency_lock:
            return await parse_file(
                path, descriptor_type="network-status-consensus-3 1.0")

    #async def descriptor(self, doctype, digest=None, published_hint=None):
    #    if self.legacy_archive:
    #        # TODO: Check earlier days too
    #        _, path = self._descriptor_path(MARKERS[doctype], published_hint,
    #                                        digest)
    #    else:
    #        _, path = self._descriptor_digest_path(MARKERS[doctype], "sha1",
    #                                               digest)
    #    try:
    #        async with self.max_file_concurrency_lock:
    #            async with aiofiles.open(path, 'rb') as source:
    #                raw_content = await source.read()
    #                return next(await parse_bytes(raw_content))
    #    except FileNotFoundError:
    #        LOG.debug("The file was not present in the store.")
    #        return None
