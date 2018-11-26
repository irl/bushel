import asyncio
import collections
import datetime
import logging
import random
from collections import defaultdict
from itertools import chain

import stem

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel import DIRECTORY_AUTHORITIES
from bushel import DirectoryCacheMode
from bushel.cache import DirectoryCache

LOG = logging.getLogger('')

def dir_port_from_v3ident(v3ident):
    for authority in DIRECTORY_AUTHORITIES:
        if authority.v3ident == v3ident:
            return authority.dir_port

class DirectoryScraper:
    def __init__(self, archive_path):
        self.cache = DirectoryCache(archive_path)

    async def discover_consensus(self, flavor="ns", *, next_consensus=True,
                                 endpoint=None):
        """
        Fetches either the current or next consensus of a given flavor.

        :param str flavor: The flavor of consensus to retrieve.
        :param bool next_vote: If *True*, the next vote will be fetched instead
                               of the current vote.

        :returns: A
                  :py:class:`~stem.descriptor.network_status.NetworkStatusDocumentV3`
                  for the requested consensus.
        """
        # TODO: Add support for next and endpoint
        return await self.cache.consensus(flavor)

    async def _discover_votes_from_status(self, status):
        votes = []
        if status.is_consensus:
            votes += await asyncio.gather(*[
                self.cache.vote(
                    authority.v3ident,
                    digest=authority.vote_digest)
                for authority in status.directory_authorities
            ])
        return [v for v in votes if v]

    async def _discover_votes_directly(self, next_vote):
        votes = await asyncio.gather(*[self.cache.vote(v3ident=authority.v3ident)
                                       for authority in DIRECTORY_AUTHORITIES])
        return [v for v in votes if v]

    async def discover_votes(self, status=None, next_vote=False):
        """
        Retrieves either the current or next votes. Votes are discovered by
        fetching each directory's own vote. To discover votes from a consensus
        see :py:meth:`DirectoryScraper.scrape_consensus`.

        :param bool next_vote: If *True*, the next vote will be fetched instead
                               of the current vote.

        :returns: A list of
                  :py:class:`~stem.descriptor.network_status.NetworkStatusDocumentV3`
                  containing all discovered votes.
        """
        if status:
            return await self._discover_votes_from_status(status)
        else:
            return await self._discover_votes_directly(next_vote)

    async def discover_server_descriptors(self,
                                          statuses,
                                          endpoint_preference=True):
        """
        Retrieves the server descriptors referenced by *statuses*. In the case
        that descriptors are referenced by a vote, this hint will be provided
        to the cache.

        :param bool next_vote: If *True*, the next vote will be fetched instead
                               of the current vote.

        :returns: A list of
                  :py:class:`~stem.descriptor.server_descriptor.RelayDescriptor`
                  containing all discovered votes.
        """
        digests = []
        for status in statuses:
            if not status.is_microdescriptor:
                digests += [status_entry.digest for status_entry in status.routers.values()]
        digests = list(set(digests))
        return await self.cache.relay_server_descriptors(
                digests, published_hint=status.valid_after)

    async def discover_extra_info_descriptors(self, server_descriptors):
        return await self.cache.relay_extra_info_descriptors(
            [desc.extra_info_digest
            for desc in server_descriptors
            if desc.extra_info_digest])

    async def discover_microdescriptors(self, statuses):
        microdescriptors = []
        for status in statuses:
            if status.is_microdescriptor:
                microdescriptors += await self.cache.relay_microdescriptors([
                    status_entry.microdescriptor_digest
                    for status_entry in status.routers.values()
                    if status_entry.microdescriptor_digest
                ])
        return microdescriptors

    async def _scrape(self, directory_cache_mode):
        self.cache.set_mode(directory_cache_mode)
        statuses = await self.discover_votes()
        consensus = await self.discover_consensus()
        statuses.append(consensus)
        consensus = await self.discover_consensus("microdesc")
        statuses.append(consensus)
        statuses += await self.discover_votes(consensus)
        server_descriptors = await self.discover_server_descriptors(
            statuses,
            endpoint_preference=directory_cache_mode is
            DirectoryCacheMode.DIRECTORY_CACHE)
        microdescriptors = await self.discover_microdescriptors(statuses)
        extra_info_descriptors = await self.discover_extra_info_descriptors(
            server_descriptors)

    async def scrape_as_client(self):
        await self._scrape(DirectoryCacheMode.CLIENT)

    async def scrape_as_directory_cache(self):
        await self._scrape(DirectoryCacheMode.DIRECTORY_CACHE)

async def scrape(args):
    scraper = DirectoryScraper(args.archive_path)
    if args.client:
        await scraper.cache.downloader.relay_consensus()
        await scraper.scrape_as_client()
    else:
        await scraper.scrape_as_directory_cache()
