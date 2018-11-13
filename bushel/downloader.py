import asyncio
import collections
import logging
import socket
import sys
import traceback
import urllib.error

from random import randint

import stem
from stem import DirPort
from stem import ORPort
from stem.descriptor.remote import DescriptorDownloader

from bushel.store import FilesystemStore

DIRECTORY_AUTHORITIES = [
    DirPort("128.31.0.39", 9131),  # moria1
    ORPort("86.59.21.38", 443),  # tor26
    DirPort("194.109.206.212", 80),  # dizum
    DirPort("131.188.40.189", 80),  # gabelmoo
    DirPort("193.23.244.244", 80),  # dannenberg
    DirPort("171.25.193.9", 443),  # maatuska
    DirPort("154.35.175.225", 80),  # Faravahar
    DirPort("199.58.81.140", 80),  # longclaw
    DirPort("204.13.164.11", 80),  # bastet
]

LOG = logging.getLogger('')

SERVER_DESCRIPTOR = 10
EXTRA_INFO_DESCRIPTOR = 20


def resource_url(doctype, fingerprint=None, digest=None):
    """
    Builds a URL to be used to download a resource.

    To fetch all available server descriptors, for example (please don't do
    this regularly unless using your own local directory cache):

    >>> resource_url(SERVER_DESCRIPTOR)
    '/tor/server/all'

    To fetch a specific server descriptor, you can specify a *fingerprint* or
    a *digest*:

    >>> resource_url(SERVER_DESCRIPTOR,
    ...              fingerprint="CF0CC69DE1E7E75A2D995FD8D9FA7D20983531DA")
    '/tor/server/fp/CF0CC69DE1E7E75A2D995FD8D9FA7D20983531DA'

    .. warning:: If both a digest and fingerprint are specified, strange and
                 unpredictable things may happen.

    To fetch multiple descriptors simultaneously, you can pass a list to the
    fingerprint or digest parameters. In the generated URL, these will be
    sorted such that any ordering of the same fingerprints or digests will
    always produce the same URL (although the sorting algorithm may change
    between releases).

    >>> resource_url(SERVER_DESCRIPTOR,
    ...              fingerprint=["E59CC0060074E14CA8E9469999B862C5E1CE49E9",
    ...                           "CF0CC69DE1E7E75A2D995FD8D9FA7D20983531DA"])
    '/tor/server/fp/CF0CC69DE1E7E75A2D995FD8D9FA7D20983531DA+E59CC0060074E14CA8E9469999B862C5E1CE49E9'
    """
    if fingerprint is None and digest is None:
        suffix = "all"
    elif fingerprint is not None:
        suffix = "fp/"
        if isinstance(fingerprint, list):
            suffix += "+".join(sorted(fingerprint))
        else:
            suffix += fingerprint
    else:  # digest must be set
        suffix = "d/"
        if isinstance(digest, list):
            suffix += "+".join(sorted(digest))
        else:
            suffix += digest
    if doctype is SERVER_DESCRIPTOR:
        return "/tor/server/" + suffix
    if doctype is EXTRA_INFO_DESCRIPTOR:
        return "/tor/extra/" + suffix
    raise RuntimeError("Unknown document type requested")


class DirectoryDownloader:
    """
    The :py:class:`DirectoryDownloader` provides an asyncio-compatible
    wrapper around the stem DescriptorDownloader, with two modes of operation:

    * Directory Cache ([dir-spec]_ §4)
    * Client ([dir-spec]_ §5)

    The DirectoryDownloader will not initiate downloads on its own intiative.
    It must be driven to perform downloads through the methods provided.

    .. note:: As a valid consensus is required to implement parts of the
              functionality, the latest consensus is cached internally. This
              cached consensus should not be relied upon by external code. The
              cached consensus will never be served as a response to a request
              for a consensus.

    .. warning:: Switching between directory cache and client modes clears the
                 state that records which servers have been queries for
                 descriptors and will allow another request to be made. Ensure
                 that you are not switching modes too often.
    """

    def __init__(self,
                 initial_consensus=None,
                 endpoints=None,
                 max_concurrency=5):
        self.max_concurrency_lock = asyncio.BoundedSemaphore(max_concurrency)
        self.current_consensus = initial_consensus
        self._set_endpoints(endpoints or DIRECTORY_AUTHORITIES)
        self.downloader = DescriptorDownloader(
            timeout=5,
            retries=0,
        )

    def _set_endpoints(self, endpoints):
        self.endpoints = endpoints
        self.endpoint_requests = {x: [] for x in endpoints}

    def authorities(self):
        """
        Usually returns a list containing either a DirPort or an ORPort for
        each of the directory authorities.

        If endpoints have been manually set and the list of endpoints does not
        contain a known directory authority, then the list of endpoints is
        returned instead. This is to allow for testing with a local directory
        cache, or in testing networks.
        """
        for authority in DIRECTORY_AUTHORITIES:
            if authority in self.endpoints:
                return DIRECTORY_AUTHORITIES
        return self.endpoints

    def directory_caches(self):
        """
        Usually returns a list containing either a DirPort or an ORPort for
        each of the directory caches known from the latest consensus. If no
        consensus is known, this will return
        :py:func:`DirectoryDownloader.authorities()` instead.

        If endpoints have been manually set and the list of endpoints does not
        contain a known directory authority, then the list of endpoints is
        returned instead. This is to allow for testing with a local directory
        cache, or in testing networks.
        """
        raise NotImplementedError()

    def _consensus_is_fresh(self):
        """
        Returns True if the latest known consensus is both valid and fresh,
        otherwise False.
        """
        raise NotImplementedError()

    async def consensus(self, endpoint=None):
        query = self.downloader.get_consensus(
            document_handler=stem.descriptor.DocumentHandler.DOCUMENT,
            endpoints=[endpoint] if endpoint else self.authorities())
        LOG.debug("Started consensus download")
        while not query.is_done:
            await asyncio.sleep(1)
        LOG.debug("Consensus download completed successfully")
        try:
            result = query.run()  # This will throw any exceptions, the query
            # is already done so this doesn't block.
            self.current_consensus = result[0]
            return result[0]
        except (urllib.error.URLError, socket.timeout, ValueError) as e:
            LOG.error("Failed to download a consensus!")

    async def descriptor(self, doctype, digest=None, endpoint=None):
        async with self.max_concurrency_lock:
            query = self.downloader.query(
                resource_url(doctype, digest=digest),
                endpoints=[endpoint] if endpoint else self.endpoints)
            while not query.is_done:
                await asyncio.sleep(1)
            query.run()
            return [d for d in query]
