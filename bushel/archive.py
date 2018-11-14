import os
import os.path
import logging
from io import BytesIO

import aiofiles

from stem.descriptor import parse_file
from stem.descriptor.server_descriptor import RelayDescriptor
from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor
from stem.descriptor.networkstatus import NetworkStatusDocumentV3

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR

LOG = logging.getLogger('')

SERVER_DESCRIPTOR_MARKER = "server-descriptors"
EXTRA_INFO_DESCRIPTOR_MARKER = "extra-infos"

MARKERS = {
    SERVER_DESCRIPTOR: SERVER_DESCRIPTOR_MARKER,
    EXTRA_INFO_DESCRIPTOR: EXTRA_INFO_DESCRIPTOR_MARKER,
}

class DirectoryArchive:
    """
    Persistent filesystem-backed archive for Tor directory protocol
    descriptors. This is intended to scale to decades worth of descriptors.

    This class implements a superset of the CollecTor filesystem protocol as
    detailed in [collector-protocol]_. The additional functionality is used
    to allow quick retrieval of descriptors by their digest by creating a
    parallel directory hierachy containing symlinks. The assumption is that
    the filesystem has better data structures for traversing a hash tree than
    can be hacked on in the time available for this prototype. This extra
    functionality may disappear in later versions.
    """

    def __init__(self, archive_path, legacy_archive=False):
        """
        Hi.

        :param str archive_path: Either an absolute or relative path to the
                                 location of the directory to use for the
                                 archive. This location must exist, but may
                                 be an empty directory.
        :param bool legacy_archive: If True, disables the use of symlinks for
                                    faster descriptor retrieval.
        """
        self.archive_path = archive_path
        self.legacy_archive = legacy_archive

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
            dpath, fpath = self._consensus_path(descriptor)
        #elif type(descriptor) is NetworkStatusDocumentV3 and descriptor.is_vote:
        #dpath, fpath = self._vote_path(descriptor)
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
                             f"{marker}",
                             f"{marker}-{published.year}-{published.month:02d}",
                             f"{digest[0]}", f"{digest[1]}")
        fpath = os.path.join(dpath, f"{digest}")
        return dpath, fpath

    def _consensus_path(self, consensus):
        va = consensus.valid_after
        dpath = os.path.join(
            self.archive_path, "relay-descriptors", "consensuses",
            f"consensuses-{va.year}-{va.month:02d}", f"{va.day}")
        fpath = os.path.join(
            dpath,
            f"{va.year}-{va.month:02d}-{va.day:02d}-{va.hour:02d}-{va.minute:02d}-{va.second:02d}-consensus"
        )
        return dpath, fpath

    def _type_annotation_for(self, descriptor):
        annotations = {
            RelayDescriptor: b"server-descriptor 1.0",
            RelayExtraInfoDescriptor: b"extra-info 1.0",
        }

        # stem uses the same class for both consensus and votes so we need
        # to have special logic for that
        if isinstance(descriptor, NetworkStatusDocumentV3):
            if descriptor.is_consensus:
                return b"network-status-consensus-3 1.0"
            elif descriptor.is_vote:
                return b"network-status-vote-3 1.0"
            else:
                raise RuntimeError(
                    "It's a network status but not a consensus or vote?")

        if type(descriptor) in annotations:
            return annotations[type(descriptor)]

    def prepare_annotated_content(self, descriptor):
        content = descriptor.get_bytes()
        type_annotation = self._type_annotation_for(descriptor)
        if type_annotation is not None:
            return b"@type " + type_annotation + b"\r\n" + content
        return content

    async def store(self, descriptor):
        path = self.path_for(descriptor, create_dir=True)
        async with aiofiles.open(path, 'wb') as output:
            await output.write(self.prepare_annotated_content(descriptor))
        if not isinstance(descriptor, NetworkStatusDocumentV3):
            # TODO: Create symlinks for descriptors too
            digest_path = self.digest_path_for(descriptor, "sha1", create_dir=True)
            # TODO: Make the symlink async
            os.symlink(os.path.abspath(path), digest_path)

    async def descriptor(self, doctype, digest=None, published_hint=None):
        if self.legacy_archive:
            # TODO: Check earlier days too
            _, path = self._descriptor_path(MARKERS[doctype], digest, published_hint)
        else:
            _, path = self._descriptor_digest_path(MARKERS[doctype], "sha1", digest)
        try:
            async with aiofiles.open(path, 'rb') as source:
                raw_content = await source.read()
                # TODO: We use BytesIO here because it's not clear to me how
                # to parse a string to get a descriptor instead of a file.
                desc = BytesIO(raw_content)
                return next(parse_file(desc))
        except FileNotFoundError:
            LOG.debug("The file was not present in the store.")
            return None
