import asyncio
import logging
import socket
import urllib.error

import stem
from stem import DirPort
from stem.descriptor.remote import DescriptorDownloader

from bushel import DIRECTORY_AUTHORITIES
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel import SERVER_DESCRIPTOR

LOG = logging.getLogger('')



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
    The :py:class:`DirectoryDownloader` provides an
    :py:mod:`asyncio`-compatible wrapper around the stem
    :py:class:`~stem.descriptor.remote.DescriptorDownloader`, with two modes of
    operation:

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
                 state that records which servers have been queried for
                 descriptors and should not have further requests made. Ensure
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
        Usually returns a list containing either a :py:class:`~stem.DirPort` or
        an :py:class:`~stem.ORPort` for each of the directory authorities.

        If endpoints have been manually set and the list of endpoints does not
        contain a known directory authority, then the list of endpoints is
        returned instead. This is to allow for testing with a local directory
        cache, or in testing networks.
        """
        for authority in DIRECTORY_AUTHORITIES:
            if authority in self.endpoints:
                return DIRECTORY_AUTHORITIES.copy()
        return self.endpoints

    def directory_caches(self, extra_info=False):
        """
        Usually returns a list containing either a DirPort or an ORPort for
        each of the directory caches known from the latest consensus. If no
        consensus is known, this will return
        :py:meth:`~DirectoryDownloader.authorities()` instead.

        If endpoints have been manually set and the list of endpoints does not
        contain a known directory authority, then the list of endpoints is
        returned instead. This is to allow for testing with a local directory
        cache, or in testing networks.

        :param bool extra_info: Whether the list returned should contain only
                                directory caches that cache extra-info
                                descriptors.
        """
        if self.current_consensus is None:
            # TODO: Check also that it's fresh!
            return self.authorities()
        for authority in DIRECTORY_AUTHORITIES:
            if authority in self.endpoints:
                directory_caches = DIRECTORY_AUTHORITIES.copy()
                for router in self.current_consensus.routers.entries():
                    if stem.Flag.V2DIR in router.flags and ( # pylint: disable=no-member
                            not extra_info or router.extra_info_cache):
                        directory_caches.append(
                            DirPort(router.address, router.dir_port))
                return directory_caches
        return DIRECTORY_AUTHORITIES.copy()

    def _consensus_is_fresh(self):
        """
        Returns True if the latest known consensus is both valid and fresh,
        otherwise False.
        """
        raise NotImplementedError()

    async def consensus(self, endpoint=None, supress=True):
        query = self.downloader.get_consensus(
            document_handler=stem.descriptor.DocumentHandler.DOCUMENT, # pylint: disable=no-member
            endpoints=[endpoint] if endpoint else self.authorities())
        LOG.debug("Started consensus download")
        while not query.is_done:
            await asyncio.sleep(1)
        LOG.debug("Consensus download completed successfully")
        try:
            if not supress:
                query.run()  # This will throw any exceptions, the
                # query is already done so this doesn't block.
            for consensus in query:
                self.current_consensus = consensus
                return consensus
        except (urllib.error.URLError, socket.timeout, ValueError):
            LOG.error("Failed to download a consensus!")

    async def descriptor(self, doctype, digest=None, endpoint=None, supress=True):
        async with self.max_concurrency_lock:
            query = self.downloader.query(
                resource_url(doctype, digest=digest),
                endpoints=[endpoint] if endpoint else self.endpoints)
            while not query.is_done:
                await asyncio.sleep(1)
            if not supress:
                query.run()  # This will throw any exceptions, the query is
                # already done so this doesn't block.
            return [d for d in query]
