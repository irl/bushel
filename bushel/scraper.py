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

    async def discover_consensus(self, next_consensus=True, endpoint=None):
        """
        Fetches either the current or next consensus.

        :param bool next_vote: If *True*, the next vote will be fetched instead
                               of the current vote.

        :returns: A
                  :py:class:`~stem.descriptor.network_status.NetworkStatusDocumentV3`
                  for the requested consensus.
        """
        # TODO: Add support for next and endpoint
        return await self.cache.consensus()

    async def _discover_votes_from_status(self, status):
        votes = []
        if status.is_consensus:
            votes += await asyncio.gather(*[
                self.cache.vote(
                    authority.v3ident,
                    digest=authority.vote_digest,
                    valid_after=status.valid_after)
                for authority in status.directory_authorities
            ])
        return [v for v in votes if v]

    async def _discover_votes_directly(self, next_vote):
        votes = await asyncio.gather(*[self.cache.vote(v3ident=authority.v3ident,
                                                       next_vote=next_vote)
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
            return await self._discover_votes_from_statuses(statuses)
        else:
            return await self._discover_votes_directly(next_vote)

    async def discover_server_descriptors(self, statuses, endpoint_preference=True):
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
        referencing_endpoints = defaultdict(list)
        for status in statuses:
            endpoint = None
            if status.is_vote:
                endpoint = dir_port_from_v3ident(
                    status.directory_authorities[0].v3ident)
            for status_entry in status.routers.values():
                referencing_endpoints[status_entry.digest].append(endpoint)
        if endpoint_preference:
            all_endpoints = list(set(chain(*referencing_endpoints.values())))
            endpoint_assignments = defaultdict(list)
            for digest in referencing_endpoints:
                endpoint_assignments[random.choice(all_endpoints)].append(digest)
            return [s for s in chain(*await asyncio.gather(*[self.cache.descriptor(
                SERVER_DESCRIPTOR,
                digest=endpoint_assignments[assignment],
                endpoint=assignment)
                for assignment in endpoint_assignments])) if s]
        else:
            return await self.cache.descriptor(
                SERVER_DESCRIPTOR,
                digest=referencing_endpoints.keys())

    async def discover_extra_info_descriptors(self, server_descriptors):
        return await asyncio.gather(*[self.cache.descriptor(
            EXTRA_INFO_DESCRIPTOR,
            desc.extra_info_digest)
            for desc in server_descriptors])

    async def _scrape(self, directory_cache_mode):
        if directory_cache_mode is DirectoryCacheMode.DIRECTORY_CACHE:
            self.cache.set_mode(DirectoryCacheMode.DIRECTORY_CACHE)
        else:
            self.cache.set_mode(DirectoryCacheMode.CLIENT)
        # TODO: Check for unrecognised modes
        statuses = await self.discover_votes()
        statuses.append(await self.discover_consensus())
        server_descriptors = await self.discover_server_descriptors(
            statuses,
            endpoint_preference=directory_cache_mode is
            DirectoryCacheMode.DIRECTORY_CACHE)
        extra_info_descriptors = await self.discover_extra_info_descriptors(
            server_descriptors)

    async def scrape_as_client(self):
        await self._scrape(DirectoryCacheMode.CLIENT)

    async def scrape_as_directory_cache(self):
        await self._scrape(DirectoryCacheMode.DIRECTORY_CACHE)

async def scrape(args):
    scraper = DirectoryScraper(args.archive_path)
    await scraper.scrape_as_directory_cache()
