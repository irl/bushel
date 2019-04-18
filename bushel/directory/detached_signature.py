import collections
import logging

from bushel.directory.document import DirectoryDocument
from bushel.directory.document import expect_arguments
from bushel.directory.document import parse_timestamp
from bushel.directory.network_status_consensus import NetworkStatusConsensusDirectorySignature

LOG = logging.getLogger("bushel")

class DetachedSignatureAdditionalDigest(
      collections.namedtuple('DetachedSignatureAdditionalSignature',
                             ['flavor', 'algname', 'digest'])):
    """
    Additional signatures as found in :class:`DetachedSignature` s, defined in
    the Tor directory protocol version 3 ([dir-spec]_ §3.10).

    :var str flavor: flavor of the additional consensus
    :var str algname: name of algorithm used for the digest
    :var str digest: the digest of the document as signed
    """

class DetachedSignatureAdditionalSignature(
      collections.namedtuple('DetachedSignatureAdditionalSignature',
                             ['flavor', 'algname', 'identity',
                              'signing_key_digest', 'signature'])):
    """
    Additional signatures as found in :class:`DetachedSignature` s, defined in
    the Tor directory protocol version 3 ([dir-spec]_ §3.10).

    :var str flavor: flavor of the additional consensus
    :var str algname: name of algorithm used for the digest
    :var str identity:
        hex-encoded digest of the authority identity key of the signing
        authority
    :var str signing_key_digest:
        hex-encoded digest of the current authority signing key of the signing
        authority
    :var bytes signature:
        RSA signature of the OAEP+-padded SHA256 digest of the additional
        consensus
    """

class DetachedSignature(DirectoryDocument):
    """
    Detached signature documents are used as part of the consensus process for
    the Tor directory protocol version 3 (§3.10 [dir-spec]_). Once an authority
    has computed and signed a consensus network status, it should send its
    detached signature to each other authority in an HTTP POST request. All of
    the detached signatures it knows for consensus status should be available
    at:

    ``http://<hostname>/tor/status-vote/next/consensus-signatures.z``

    Assuming full connectivity, every authority should compute and sign the
    same consensus including any flavors in each period.  Therefore, it
    isn't necessary to download the consensus or any flavors of it computed
    by each authority; instead, the authorities only push/fetch each
    others' signatures.

    These documents are interesting for Tor Metrics as they allow detection of
    new consensus flavors automatically, allowing them to be archived as soon
    as they are available even if we are not yet able to parse them.

    :var str consensus_digest: digest of the consensus
    :var ~datetime.datetime valid_after: the valid-after time
    :var ~datetime.datetime fresh_until: the fresh-until time
    :var ~datetime.datetime valid_until: the valid-until time
    :var list(DetachedSignatureAdditionalDigest) additional_digests: additional digests
    :var list(DetachedSignatureAdditionalSignature) additional_signatures: additional signatures
    :var list(NetworkStatusConsensusDirectorySignature) direcory_signatures: directory signatures
    """

    def __init__(self, raw_content):
        super().__init__(raw_content)
        self.PARSE_FUNCTIONS = {
            "consensus-digest": self.parse_consensus_digest,
            "valid-after": self.parse_valid_after,
            "fresh-until": self.parse_fresh_until,
            "valid-until": self.parse_valid_until,
            "additional-digest": self.parse_additional_digest,
            "additional-signature": self.parse_additional_signature,
            "directory-signature": self.parse_directory_signature,
        }
        self.consensus_digest = None
        self.valid_after = None
        self.fresh_until = None
        self.valid_until = None
        self.additional_digests = []
        self.additional_signatures = []
        self.directory_signatures = []

    @expect_arguments(1, 1, False)
    def parse_consensus_digest(self, item):
        self.consensus_digest = item.arguments[0]

    @expect_arguments(1, 2, False)
    def parse_valid_after(self, item):
        self.valid_after = parse_timestamp(item)

    @expect_arguments(1, 2, False)
    def parse_fresh_until(self, item):
        self.fresh_until = parse_timestamp(item)

    @expect_arguments(1, 2, False)
    def parse_valid_until(self, item):
        self.valid_until = parse_timestamp(item)

    @expect_arguments(3, 3, False)
    def parse_additional_digest(self, item):
        self.additional_digests.append(DetachedSignatureAdditionalDigest(
            *item.arguments[:3]))

    @expect_arguments(4, 4, False)
    def parse_additional_signature(self, item):
        # TODO: Expect objects
        if len(item.objects) != 1:
            raise RuntimeError("Got more than one object on an additional "
                               "signature. I don't know what to do.")
        if item.objects[0].keyword != "SIGNATURE":
            raise RuntimeError("Expected object with keyword SIGNATURE on an "
                               "additional-signature object but found "
                               f"{item.objects[0].keyword}.")
        self.additional_signatures.append(DetachedSignatureAdditionalSignature(
            *item.arguments[:4], item.objects[0].data))

    @expect_arguments(2, 3, False)
    def parse_directory_signature(self, item):
        # TODO: Expect objects
        if len(item.objects) != 1:
            raise RuntimeError("Got more than one object on an additional "
                               "signature. I don't know what to do.")
        if item.objects[0].keyword != "SIGNATURE":
            raise RuntimeError("Expected object with keyword SIGNATURE on an "
                               "additional-signature object but found "
                               f"{item.objects[0].keyword}.")
        if len(item.arguments) is 2:
            arguments = (None, *item.arguments)
        else:
            arguments = item.arguments[:3]
        self.additional_signatures.append(
            NetworkStatusConsensusDirectorySignature(
                *arguments, item.objects[0].data))

    def is_valid(self):
        # TODO: Validate the document
        pass

    def to_stem(self):
        from stem.descriptor.networkstatus import DetachedSignature as StemDetachedSignature
        return StemDetachedSignature(self.get_bytes())
