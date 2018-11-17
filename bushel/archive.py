"""
Persistent filesystem-backed archive for Tor directory protocol
descriptors.
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

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR

LOG = logging.getLogger('')

SERVER_DESCRIPTOR_MARKER = "server-descriptor"
EXTRA_INFO_DESCRIPTOR_MARKER = "extra-info"

MARKERS = {
    SERVER_DESCRIPTOR: SERVER_DESCRIPTOR_MARKER,
    EXTRA_INFO_DESCRIPTOR: EXTRA_INFO_DESCRIPTOR_MARKER,
}

async def parse_bytes(descriptor_bytes, **kwargs):
    return await parse_file(io.BytesIO(descriptor_bytes), **kwargs)

async def parse_file(*args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None,
                                      functools.partial(stem_parse_file,
                                                        *args, **kwargs))

async def aglob(pathname, recursive=False):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None,
                                      functools.partial(glob.glob,
                                                        pathname,
                                                        recursive=recursive))

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

    def __init__(self, archive_path, legacy_archive=False,
                 max_file_concurrency=50):
        self.archive_path = archive_path
        self.legacy_archive = legacy_archive
        self.max_file_concurrency_lock = asyncio.BoundedSemaphore(
            max_file_concurrency)

    def digest_path_for(self, descriptor, algo="sha1", create_dir=False):
        if self.legacy_archive:
            raise RuntimeError("Cannot get a digest path for descriptors in a "
                               "legacy archive.")
        if algo == "sha1":
            digest = descriptor.digest()
        else:
            raise RuntimeError(
                "Unknown digest algorithm requested for symlink path")
        if isinstance(descriptor, RelayDescriptor):
            dpath, fpath = self._descriptor_digest_path(
                SERVER_DESCRIPTOR_MARKER, algo, digest)
        elif isinstance(descriptor, RelayExtraInfoDescriptor):
            dpath, fpath = self._descriptor_digest_path(
                EXTRA_INFO_DESCRIPTOR_MARKER, algo, digest)
        elif isinstance(descriptor, NetworkStatusDocumentV3) \
              and descriptor.is_consensus:
            dpath, fpath = "/tmp", "/tmp/consensus"
        else:
            print(repr(descriptor))
            raise RuntimeError(
                f"Attempted to store unknown descriptor type {type(descriptor)}"
            )
        if create_dir:
            os.makedirs(dpath, exist_ok=True)
        return fpath

    def _descriptor_digest_path(self, marker, algo, digest):
        digest = digest.lower()
        dpath = os.path.join(self.archive_path, "relay-descriptors",
                             f"{marker}", f"by-{algo}",
                             *[f"{digest[i]}" for i in range(0, 10)])
        fpath = os.path.join(dpath, f"{digest}")
        return dpath, fpath

    def path_for(self, descriptor, create_dir=False):
        """
        The filesystem path that a descriptor will be archived at. These paths
        are defined in [collector-protocol]_:

        ========================= ==================
        Descriptor Types          Section
        ========================= ==================
        Consensuses               §5.3.2
        Votes                     §5.3.2
        Server Descriptors        §5.3.2
        Extra Info Descriptors    §5.3.2
        ========================= ==================

        :param bool create_dir: Create the directory ready to archive a
                                descriptor.

        :returns: URL resource string that may be used with stem's
                  :py:class:`stem.descriptor.remote.Query`.
        """
        if isinstance(descriptor, RelayDescriptor):
            dpath, fpath = self._descriptor_path(SERVER_DESCRIPTOR_MARKER,
                                                 descriptor.published,
                                                 descriptor.digest())
        elif isinstance(descriptor, RelayExtraInfoDescriptor):
            dpath, fpath = self._descriptor_path(EXTRA_INFO_DESCRIPTOR_MARKER,
                                                 descriptor.published,
                                                 descriptor.digest())
        elif isinstance(descriptor, NetworkStatusDocumentV3) and \
              descriptor.is_consensus:
            dpath, fpath = self._consensus_path(descriptor.valid_after)
        elif isinstance(descriptor, NetworkStatusDocumentV3) and \
              descriptor.is_vote:
            # TODO: The digest functionality should be appearing in stem.
            # https://trac.torproject.org/projects/tor/ticket/28398
            raw_content, ending = str(descriptor), "\ndirectory-signature "
            raw_content = stem.util.str_tools._to_bytes(
                raw_content[:raw_content.find(ending) + len(ending)])
            digest = hashlib.sha1(raw_content).hexdigest().upper()
            dpath, fpath = self._vote_path(
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

    def _descriptor_path(self, marker, published, digest):
        digest = digest.lower()
        dpath = os.path.join(self.archive_path, "relay-descriptors",
                             f"{marker}", f"{published.year}",
                             f"{published.month:02d}", f"{digest[0]}",
                             f"{digest[1]}")
        fpath = os.path.join(dpath, f"{digest}")
        return dpath, fpath

    def _consensus_path(self, valid_after):
        dpath = os.path.join(
            self.archive_path, "relay-descriptors", "consensus",
            f"{valid_after.year}",
            f"{valid_after.month:02d}",
            f"{valid_after.day}")
        fpath = os.path.join(
            dpath,
            (f"{valid_after.year}-{valid_after.month:02d}-"
             f"{valid_after.day:02d}-{valid_after.hour:02d}-"
             f"{valid_after.minute:02d}-{valid_after.second:02d}-consensus"))
        return dpath, fpath

    async def store(self, descriptor):
        path = self.path_for(descriptor, create_dir=True)
        async with self.max_file_concurrency_lock:
            async with aiofiles.open(path, 'wb') as output:
                await output.write(prepare_annotated_content(descriptor))
            if not isinstance(descriptor, NetworkStatusDocumentV3):
                # TODO: Create symlinks for descriptors too
                digest_path = self.digest_path_for(
                    descriptor, "sha1", create_dir=True)
                # TODO: Make the symlink async
                os.symlink(os.path.abspath(path), digest_path)

    def _vote_path(self, valid_after, v3ident, digest):
        dpath = os.path.join(self.archive_path, "relay-descriptors", "vote",
                             f"{valid_after.year}", f"{valid_after.month}",
                             f"{valid_after.day}")
        fpath = os.path.join(
            dpath, (f"{valid_after.year}-{valid_after.month:02d}-"
                    f"{valid_after.day:02d}-{valid_after.hour:02d}-"
                    f"{valid_after.minute:02d}-{valid_after.second:02d}-vote-"
                    f"{v3ident}-{digest}"))
        return dpath, fpath

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
                                     consensus that became valid at the top
                                     of the current hour will be retrieved.
        """
        if valid_after is None:
            valid_after = datetime.datetime.utcnow()
            valid_after = valid_after.replace(minute=0, second=0)
        _, path = self._vote_path(valid_after, v3ident, digest)
        if digest == "*":
            try:
                path = (await aglob(path))[0]
            except IndexError:
                LOG.debug("The file was not present in the store.")
                return None
        try:
            async with self.max_file_concurrency_lock:
                async with aiofiles.open(path, 'rb') as source:
                    raw_content = await source.read()
                return next(
                    await parse_bytes(
                        raw_content,
                        document_handler=DocumentHandler.DOCUMENT)) # pylint: disable=no-member
        except FileNotFoundError:
            LOG.debug("The file was not present in the store.")
            return None

    async def consensus(self, valid_after=None):
        """
        Retrieves a consensus from the archive.

        :param datetime valid_after: If set, will retrieve a consensus with the
                                     given valid_after time, otherwise a
                                     consensus that became valid at the top
                                     of the current hour will be retrieved.
        """
        if valid_after is None:
            valid_after = datetime.datetime.utcnow()
            valid_after = valid_after.replace(minute=0, second=0)
        _, path = self._consensus_path(valid_after)
        try:
            async with self.max_file_concurrency_lock:
                async with aiofiles.open(path, 'rb') as source:
                    raw_content = await source.read()
                return next(
                    await parse_bytes(
                        raw_content,
                        document_handler=DocumentHandler.DOCUMENT)) # pylint: disable=no-member
        except FileNotFoundError:
            LOG.debug("The file was not present in the store.")
            return None

    async def descriptor(self, doctype, digest=None, published_hint=None):
        if self.legacy_archive:
            # TODO: Check earlier days too
            _, path = self._descriptor_path(MARKERS[doctype], published_hint,
                                            digest)
        else:
            _, path = self._descriptor_digest_path(MARKERS[doctype], "sha1",
                                                   digest)
        try:
            async with self.max_file_concurrency_lock:
                async with aiofiles.open(path, 'rb') as source:
                    raw_content = await source.read()
                    return next(await parse_bytes(raw_content))
        except FileNotFoundError:
            LOG.debug("The file was not present in the store.")
            return None
