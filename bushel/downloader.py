import asyncio
import functools
import logging
import random
import socket
import urllib.error
from itertools import chain

import stem
from stem import DirPort
from stem.descriptor.remote import MAX_FINGERPRINTS
from stem.descriptor.remote import MAX_MICRODESCRIPTOR_HASHES
from stem.descriptor.remote import DescriptorDownloader

from bushel import DIRECTORY_AUTHORITIES
from bushel import LOCAL_DIRECTORY_CACHE
from bushel import SERVER_DESCRIPTOR
from bushel import DirectoryCacheMode

LOG = logging.getLogger('')

chunks = lambda l, n: [l[i:i + n] for i in range(0, len(l), n)]


def relay_server_descriptors_query_path(digests):
    """
    Generates a query path to request server descriptors by digests from a
    directory server.  For example:

    >>> digests = ["A94A07B201598D847105AE5FCD5BC3AB10124389",
    ...            "B38974987323394795879383ABEF4893BD4895A8"]
    >>> relay_server_descriptors_query_path(digests)  # doctest: +ELLIPSIS
    '/tor/server/d/A94A07B201598D847105...24389+B3897498732339479587...95A8'

    These query paths are defined in appendix B of [dir-spec]_.

    :param list(str) digests: The hex-encoded SHA-1 digests for the
                              descriptors.

    :returns: Query path as a :py:class:`str`.
    """
    return "/tor/server/d/" + "+".join(digests)


def relay_extra_info_descriptors_query_path(digests):
    """
    Generates a query path to request extra-info descriptors by digests
    from a directory server.  For example:

    >>> digests = ["A94A07B201598D847105AE5FCD5BC3AB10124389",
    ...            "B38974987323394795879383ABEF4893BD4895A8"]
    >>> relay_extra_info_descriptors_query_path(digests)  # doctest: +ELLIPSIS
    '/tor/extra/d/A94A07B201598D847105...24389+B3897498732339479587...95A8'

    These query paths are defined in appendix B of [dir-spec]_.

    :param list(str) digests: The hex-encoded SHA-1 digests for the
                              descriptors.

    :returns: Query path as a :py:class:`str`.
    """
    return "/tor/extra/d/" + "+".join(digests)

def relay_microdescriptors_query_path(microdescriptor_hashes):
    """
    Generates a query path to request microdescriptors by their hashes
    from a directory server.  For example:

    >>> microdescriptor_hashes = ["Z62HG1C9PLIVs8jLi1guO48rzPdcq6tFTLi5s27Zy4U",
    ...                           "FkiLuQJe/Gqp4xsHfheh+G42TSJ77AarHOGrjazj0Q0"]
    >>> relay_microdescriptors_query_path(microdescriptor_hashes)  # doctest: +ELLIPSIS
    '/tor/micro/d/Z62HG1C9PLIVs8jL...Li5s27Zy4U-FkiLuQJe/Gqp4xsHf...rjazj0Q0'

    These query paths are defined in appendix B of [dir-spec]_.

    :param list(str) digests: The base64-encoded hashes for the descriptors.

    :returns: Query path as a :py:class:`str`.
    """
    return "/tor/micro/d/" + "-".join(microdescriptor_hashes)


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
    """

    def __init__(self,
                 initial_consensus=None,
                 directory_cache_mode=None,
                 max_concurrency=9):
        self.max_concurrency_lock = asyncio.BoundedSemaphore(max_concurrency)
        self.current_consensus = initial_consensus
        self.set_mode(directory_cache_mode
                      or DirectoryCacheMode.DIRECTORY_CACHE)
        self.downloader = DescriptorDownloader(
            timeout=5,
            retries=0,
        )
        self.descriptor_cache = None

    def set_mode(self, directory_cache_mode):
        if directory_cache_mode == DirectoryCacheMode.DIRECTORY_CACHE:
            self.endpoints = \
                self.extra_info_endpoints = self.directory_authorities()
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
            LOG.warning(
                "Tried to use directory caches but we don't have a consensus")
            return self.directory_authorities()
        directory_caches = [a.dir_port for a in DIRECTORY_AUTHORITIES]
        for router in self.current_consensus.routers.values():
            if extra_info and self.descriptor_cache:
                server_descriptor = self.descriptor_cache(
                    SERVER_DESCRIPTOR, router.digest)
                if (not server_descriptor) or (
                        not server_descriptor.extra_info_cache):
                    continue
            if stem.Flag.V2DIR in router.flags and router.dir_port:  # pylint: disable=no-member
                directory_caches.append(
                    DirPort(router.address, router.dir_port))
        return directory_caches

    async def _consensus_attempt(self, flavor, endpoint):
        query = self.downloader.query(
            f"/tor/status-vote/current/consensus-{flavor}",
            document_handler=stem.descriptor.DocumentHandler.DOCUMENT,  # pylint: disable=no-member
            endpoints=[endpoint])
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, functools.partial(query.run, suppress=True))
        for consensus in result:
            self.current_consensus = consensus
            return consensus

    async def relay_consensus(self, flavor="ns", valid_after=None, *, endpoint=None):
        endpoints = self.endpoints.copy()
        random.shuffle(endpoints)
        for endpoint in endpoints:
            consensus = await self._consensus_attempt(flavor, endpoint)
            if consensus:
                return consensus

    async def vote(self,
                   valid_after=None,
                   v3ident=None,
                   digest="*",
                   endpoint=None):
        if digest == "*":
            url = f"/tor/status-vote/current/authority"
            #url = f"/tor/status-vote/{'next' if next_vote else 'current'}/authority"
        else:
            url = f"/tor/status-vote/current/d/{digest}"
        query = self.downloader.query(
            url,
            document_handler=stem.descriptor.DocumentHandler.DOCUMENT,  # pylint: disable=no-member
            endpoints=[endpoint] if endpoint else self.directory_authorities())
        LOG.debug("Started consensus download")
        while not query.is_done:
            await asyncio.sleep(1)
        LOG.debug("Vote download completed successfully")
        for vote in query:
            return vote

    async def _multiple_descriptors(self, query_path_function, digests,
                                    endpoints):
        loop = asyncio.get_running_loop()
        descriptors = []
        endpoints = endpoints.copy()
        random.shuffle(endpoints)
        while endpoints and digests:
            endpoint = endpoints.pop()
            async with self.max_concurrency_lock:
                query = self.downloader.query(
                    query_path_function(digests), endpoints=[endpoint])
                result = await loop.run_in_executor(
                    None, functools.partial(query.run, suppress=True))
            for descriptor in result:
                try:
                    digests.remove(descriptor.digest())
                except ValueError:
                    LOG.error("I was given a descriptor I didn't ask for! This "
                              "likely indicated a bug in the server we used.")
                descriptors.append(descriptor)
        if digests:
            LOG.warning("Downloader failed to find descriptors: %s.",
                        query_path_function(digests))
        return descriptors

    async def relay_server_descriptors(self, digests, published_hint=None):
        """
        Retrieves multiple server descriptors from directory servers.

        :param list(str) digests: Hex-encoded digests for the descriptors.
        :param ~datetime.datetime published_hint: Provides a hint on the
            published time. Currently this is unused, but is accepted for
            compatibility with other directory sources. In the future this may
            be used to avoid attempts to download descriptors that it is likely
            are long gone.

        :returns: A :py:class:`list` of
                  :py:class:`stem.descriptor.server_descriptor.RelayDescriptor`.
        """
        batches = chunks(digests, MAX_FINGERPRINTS)
        return list(
            chain(*await asyncio.gather(*[
                self._multiple_descriptors(relay_server_descriptors_query_path,
                                           batch, self.endpoints)
                for batch in batches
            ])))

    async def relay_extra_info_descriptors(self, digests, published_hint=None):
        """
        Retrieves multiple extra-info descriptors from directory servers.

        :param list(str) digests: Hex-encoded digests for the descriptors.
        :param ~datetime.datetime published_hint: Provides a hint on the
            published time. Currently this is unused, but is accepted for
            compatibility with other directory sources. In the future this may
            be used to avoid attempts to download descriptors that it is likely
            are long gone.

        :returns: A :py:class:`list` of
                  :py:class:`stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor`.
        """
        batches = chunks(digests, MAX_FINGERPRINTS)
        return list(
            chain(*await asyncio.gather(*[
                self._multiple_descriptors(
                    relay_extra_info_descriptors_query_path, batch,
                    self.extra_info_endpoints) for batch in batches
            ])))

    async def relay_microdescriptors(self, microdescriptor_hashes, valid_after_hint=None):
        """
        Retrieves multiple server descriptors from directory servers.

        :param list(str) hashes: base64-encoded hashes for the microdescriptors.
        :param ~datetime.datetime valid_after_hint: Provides a hint on the
            valid_after time. Currently this is unused, but is accepted for
            compatibility with other directory sources. In the future this may
            be used to avoid attempts to download descriptors that it is likely
            are long gone.

        :returns: A :py:class:`list` of
                  :py:class:`stem.descriptor.microdescriptor.Microdescriptor`.
        """
        batches = chunks(microdescriptor_hashes, MAX_MICRODESCRIPTOR_HASHES)
        return list(
            chain(*await asyncio.gather(*[
                self._multiple_descriptors(relay_microdescriptors_query_path,
                                           batch, self.endpoints)
                for batch in batches
            ])))
