import os
import os.path
import logging

import stem.descriptor.remote

from stem.descriptor import DocumentHandler
from stem.descriptor import parse_file

from stem.descriptor.server_descriptor import RelayDescriptor
from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor
from stem.descriptor.networkstatus import NetworkStatusDocumentV3

LOG = logging.getLogger('')


class FilesystemStore:
    """
    This class implements the CollecTor filesystem protocol as detailed
    at https://gitweb.torproject.org/collector.git/tree/src/main/resources/docs/PROTOCOL.
    """

    def __init__(self, archive_path):
        self.archive_path = archive_path

    def digest_path_for(self, descriptor, algo="sha1", create_dir=False):
        if isinstance(descriptor, RelayDescriptor):
            dpath, fpath = self._relay_descriptor_digest_path(
                descriptor, "server-descriptors", algo)
        elif isinstance(descriptor, RelayExtraInfoDescriptor):
            dpath, fpath = self._relay_descriptor_digest_path(
                descriptor, "extra-infos", algo)
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

    def _relay_descriptor_digest_path(self, descriptor, marker, algo):
        if algo == "sha1":
            digest = descriptor.digest().lower()
        else:
            raise RuntimeError(
                "Unknown digest algorithm requested for symlink path")
        dpath = os.path.join(self.archive_path, "relay-descriptors",
                             f"{marker}", f"by-{algo}",
                             *[f"{digest[i]}" for i in range(0, 10)])
        fpath = os.path.join(dpath, f"{digest}")
        return dpath, fpath

    def path_for(self, descriptor, create_dir=False):
        if type(descriptor) is RelayDescriptor:
            dpath, fpath = self._relay_descriptor_path(descriptor,
                                                       "server-descriptors")
        elif type(descriptor) is RelayExtraInfoDescriptor:
            dpath, fpath = self._relay_descriptor_path(descriptor,
                                                       "extra-infos")
        elif type(descriptor
                  ) is NetworkStatusDocumentV3 and descriptor.is_consensus:
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

    def _relay_descriptor_path(self, descriptor, marker):
        pub = descriptor.published
        digest = descriptor.digest().lower()
        dpath = os.path.join(self.archive_path, "relay-descriptors",
                             f"{marker}",
                             f"{marker}-{pub.year}-{pub.month:02d}",
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
        if type(descriptor) is NetworkStatusDocumentV3:
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
        else:
            return content

    def store(self, descriptor):
        path = self.path_for(descriptor, create_dir=True)
        with open(path, 'wb') as output:
            output.write(self.prepare_annotated_content(descriptor))
        digest_path = self.digest_path_for(descriptor, "sha1", create_dir=True)
        os.symlink(os.path.abspath(path), digest_path)

    def server_descriptor(self, digest=None):
        fake = RelayDescriptor("")
        fake.digest = lambda: digest
        path = self.digest_path_for(fake)
        try:
            with open(path, 'rb') as source:
                return next(parse_file(path))
        except FileNotFoundError:
            LOG.debug("The file was not present in the store.")
            return None

    def extra_info_descriptor(self, digest=None):
        fake = RelayExtraInfoDescriptor("")
        fake.digest = lambda: digest
        path = self.digest_path_for(fake)
        try:
            with open(path, 'rb') as source:
                return next(parse_file(path))
        except FileNotFoundError:
            LOG.debug("The file was not present in the store.")
            return None
