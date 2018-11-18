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
from bushel.cache import DirectoryCache
from bushel.cache import DirectoryCacheMode

LOG = logging.getLogger('')

def dir_port_from_v3ident(v3ident):
    for authority in DIRECTORY_AUTHORITIES:
        if authority.v3ident == v3ident:
            return authority.dir_port

class DirectoryScraper:
    def __init__(self, archive_path):
        self.cache = DirectoryCache(archive_path)
        # TODO: Don't poke at the archive and downloader directly
        self.archive = self.cache.archive
        self.downloader = self.cache.downloader

    async def discover_consensus(self, next_consensus=True):
        """
        Fetches either the current or next consensus.

        :param bool next_vote: If *True*, the next vote will be fetched instead
                               of the current vote.

        :returns: A
                  :py:class:`~stem.descriptor.network_status.NetworkStatusDocumentV3`
                  for the requested consensus.
        """
        consensus = await self.archive.consensus()
        # TODO: Use the check built in to stem once it exists
        # https://trac.torproject.org/projects/tor/ticket/28448
        if not consensus or \
                datetime.datetime.utcnow() > consensus.valid_until:
            consensus = await self.downloader.consensus()
            if consensus is None:
                return
            await self.archive.store(consensus)
        return consensus
        print(self.downloader.endpoints)

    async def discover_votes(self, next_vote=False):
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
        authorities = DIRECTORY_AUTHORITIES.copy()
        random.shuffle(authorities)
        votes = []
        for authority in authorities:
            # TODO: This will return the current vote even if we want the next
            # vote
            vote = await self.archive.vote(authority.v3ident)
            if vote is None:
                vote = await self.downloader.vote(endpoint=authority.dir_port,
                                                  next_vote=next_vote)
                if vote is None:
                    continue
                await self.archive.store(vote)
            votes.append(vote)
        return votes

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

    #async def _recurse_network_status_references(self, network_status, endpoint=None):
    #    if network_status.is_consensus:
    #        authorities = [a for a in network_status.directory_authorities]
    #        random.shuffle(authorities)
    #        for authority in authorities:
    #            vote = await self.archive.vote(authority.v3ident,
    #                                           digest=authority.vote_digest,
    #                                           valid_after=network_status.valid_after)
    #            if not vote:
    #                vote = await self.downloader.vote(digest=authority.vote_digest)
    #                if vote:
    #                    await self.archive.store(vote)
    #            await self._recurse_network_status_references(vote)

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
    await scraper.cache.downloader.consensus()
    await scraper.scrape_as_client()
