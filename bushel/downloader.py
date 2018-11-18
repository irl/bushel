import asyncio
import functools
import logging
import random
import socket
import urllib.error

import stem
from stem import DirPort
from stem.descriptor.remote import DescriptorDownloader

from bushel import DIRECTORY_AUTHORITIES
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel import LOCAL_DIRECTORY_CACHE
from bushel import SERVER_DESCRIPTOR
from bushel import DirectoryCacheMode

LOG = logging.getLogger('')



def url_for(doctype, fingerprint=None, digest=None):
    """
    Builds a URL to be used to download a resource.

    To fetch all available server descriptors, for example (please don't do
    this regularly unless using your own local directory cache):

    >>> url_for(SERVER_DESCRIPTOR)
    '/tor/server/all'

    To fetch a specific server descriptor, you can specify a *fingerprint* or
    a *digest*:

    >>> url_for(SERVER_DESCRIPTOR,
    ...              fingerprint="CF0CC69DE1E7E75A2D995FD8D9FA7D20983531DA")
    '/tor/server/fp/CF0CC69DE1E7E75A2D995FD8D9FA7D20983531DA'

    .. warning:: If both a digest and fingerprint are specified, strange and
                 unpredictable things may happen.

    To fetch multiple descriptors simultaneously, you can pass a list to the
    fingerprint or digest parameters. In the generated URL, these will be
    sorted such that any ordering of the same fingerprints or digests will
    always produce the same URL (although the sorting algorithm may change
    between releases).

    >>> url_for(SERVER_DESCRIPTOR,
    ...              fingerprint=["E59CC0060074E14CA8E9469999B862C5E1CE49E9",
    ...                           "CF0CC69DE1E7E75A2D995FD8D9FA7D20983531DA"])
    '/tor/server/fp/CF0CC69DE1E7E75A2D995FD8D9FA7D20983531DA+E59CC0060074E14CA8E9469999B862C5E1CE49E9'
    """
    if fingerprint is None and digest is None:
        suffix = "all"
    elif fingerprint is not None:
        suffix = "fp/"
        if isinstance(fingerprint, str):
            suffix += fingerprint
        else:
            suffix += "+".join(sorted(list(fingerprint)))
    else:  # digest must be set
        suffix = "d/"
        if isinstance(digest, str):
            suffix += digest
        else:
            suffix += "+".join(sorted(list(digest)))
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
                 directory_cache_mode=None,
                 max_concurrency=9):
        self.max_concurrency_lock = asyncio.BoundedSemaphore(max_concurrency)
        self.current_consensus = initial_consensus
        self.set_mode(directory_cache_mode or DirectoryCacheMode.DIRECTORY_CACHE)
        self.downloader = DescriptorDownloader(
            timeout=5,
            retries=0,
        )
        self.descriptor_cache = None

    def set_mode(self, directory_cache_mode):
        if directory_cache_mode == DirectoryCacheMode.DIRECTORY_CACHE:
            self.endpoints = self.extra_info_endpoints = self.directory_authorities()
        elif directory_cache_mode == DirectoryCacheMode.CLIENT:
            self.endpoints = self.directory_caches()
            self.extra_info_endpoints = self.directory_caches(extra_info=True)
        elif directory_cache_mode == DirectoryCacheMode.TESTING:
            self.endpoints = [LOCAL_DIRECTORY_CACHE]
        # TODO: Error if we don't know what mode it is

    def directory_authorities(self):
        """
        Returns a list containing either a :py:class:`~stem.DirPort` or
        an :py:class:`~stem.ORPort` for each of the directory authorities.
        """
        return [a.dir_port for a in DIRECTORY_AUTHORITIES]

    def directory_caches(self, extra_info=False):
        """
        Returns a list containing either a DirPort or an ORPort for
        each of the directory caches known from the latest consensus. If no
        consensus is known, this will return
        :py:meth:`~DirectoryDownloader.authorities()` instead.

        :param bool extra_info: Whether the list returned should contain only
                                directory caches that cache extra-info
                                descriptors.
        """
        if self.current_consensus is None:
            # TODO: Check also that it's fresh!
            LOG.warning("Tried to use directory caches but we don't have a consensus")
            return self.directory_authorities()
        directory_caches = [a.dir_port for a in DIRECTORY_AUTHORITIES]
        for router in self.current_consensus.routers.values():
            if extra_info and self.descriptor_cache:
                server_descriptor = self.descriptor_cache(SERVER_DESCRIPTOR, router.digest)
                if (not server_descriptor) or (not server_descriptor.extra_info_cache):
                    continue
            if stem.Flag.V2DIR in router.flags and router.dir_port: # pylint: disable=no-member
                directory_caches.append(
                    DirPort(router.address, router.dir_port))
        return directory_caches

    def _consensus_is_fresh(self):
        """
        Returns True if the latest known consensus is both valid and fresh,
        otherwise False.
        """
        raise NotImplementedError()

    async def _consensus_attempt(self, endpoint):
        query = self.downloader.get_consensus(
            document_handler=stem.descriptor.DocumentHandler.DOCUMENT,  # pylint: disable=no-member
            endpoints=[endpoint] if endpoint else self.directory_authorities())
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, functools.partial(query.run, suppress=True))
        for consensus in result:
            self.current_consensus = consensus
            return consensus

    async def consensus(self, endpoint=None):
        endpoints = [endpoint] if endpoint else self.endpoints
        random.shuffle(endpoints)
        for endpoint in endpoints:
            consensus = await self._consensus_attempt(endpoint)
            if consensus:
                return consensus

    async def vote(self, valid_after=None, v3ident=None, digest="*", endpoint=None):
        if digest == "*":
            url = f"/tor/status-vote/current/authority"
            #url = f"/tor/status-vote/{'next' if next_vote else 'current'}/authority"
        else:
            url = f"/tor/status-vote/current/d/{digest}"
        query = self.downloader.query(url,
            document_handler=stem.descriptor.DocumentHandler.DOCUMENT, # pylint: disable=no-member
            endpoints=[endpoint] if endpoint else self.directory_authorities())
        LOG.debug("Started consensus download")
        while not query.is_done:
            await asyncio.sleep(1)
        LOG.debug("Vote download completed successfully")
        for vote in query:
            return vote

    async def descriptor(self, doctype, digest=None, endpoint=None):
        loop = asyncio.get_running_loop()
        if endpoint is None:
            endpoints = self.endpoints if doctype != EXTRA_INFO_DESCRIPTOR \
                else self.extra_info_endpoints
            endpoints = endpoints.copy()
            random.shuffle(endpoints)
        else:
            endpoints = [endpoint]
        attempts = 20
        for attempt_endpoint in endpoints:
            query = self.downloader.query(
                url_for(doctype, digest=digest), endpoints=[attempt_endpoint])
            result = await loop.run_in_executor(
                None, functools.partial(query.run, suppress=True))
            if result:
                return result[0]
            attempts -= 1
            if not attempts:
                break
        if endpoint:
            return await self.descriptor(doctype, digest=digest)
