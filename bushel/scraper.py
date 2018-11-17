import asyncio
import collections
import datetime
import logging
import random

import stem

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel import DIRECTORY_AUTHORITIES
from bushel.archive import DirectoryArchive
from bushel.downloader import DirectoryDownloader

LOG = logging.getLogger('')


class DirectoryScraper:
    def __init__(self, archive_path):
        self.server_descriptors = {}
        self.extra_info_descriptors = {}
        self.archive = DirectoryArchive(archive_path)
        self.downloader = DirectoryDownloader()

    async def fetch_consensus(self):
        consensus = await self.archive.consensus()
        # TODO: Use the check built in to stem once it exists
        # https://trac.torproject.org/projects/tor/ticket/28448
        if not consensus or \
                datetime.datetime.utcnow() > consensus.valid_until:
            consensus = await self.downloader.consensus()
            if consensus is None:
                return
            await self.archive.store(consensus)
        await self._recurse_network_status_references(consensus)

    async def fetch_votes(self, next_vote=False):
        authorities = DIRECTORY_AUTHORITIES.copy()
        random.shuffle(authorities)
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
            await self._recurse_network_status_references(vote,
                                                          endpoint=authority.dir_port)

    async def _recurse_network_status_references(self, network_status, endpoint=None):
        wanted_digests = collections.deque()
        download_tasks = []

        if network_status.is_consensus:
            authorities = [a for a in network_status.directory_authorities]
            random.shuffle(authorities)
            for authority in authorities:
                vote = await self.archive.vote(authority.v3ident,
                                               digest=authority.vote_digest,
                                               valid_after=network_status.valid_after)
                if not vote:
                    vote = await self.downloader.vote(digest=authority.vote_digest)
                    if vote:
                        await self.archive.store(vote)
                await self._recurse_network_status_references(vote)

        # Download server descriptors
        server_descriptors = []
        for desc in network_status.routers.values():
            server_descriptor = self.server_descriptors.get(
                desc.digest, None)
            if server_descriptor is None:
                server_descriptor = await self.archive.descriptor(
                    SERVER_DESCRIPTOR,
                    digest=desc.digest)
            if server_descriptor is None:
                wanted_digests.append(desc.digest)
            else:
                self.server_descriptors[desc.digest] = server_descriptor
                server_descriptors.append(server_descriptor)
        while wanted_digests:
            next_batch = [
                wanted_digests.popleft() for _i in range(
                    min(
                        len(wanted_digests),
                        stem.descriptor.remote.MAX_FINGERPRINTS))
            ]
            download_tasks.append(
                self.downloader.descriptor(
                    SERVER_DESCRIPTOR, digest=next_batch, endpoint=endpoint))
        await self.downloader.perform_downloads()
        for result in await asyncio.gather(*download_tasks):
            for desc in result:
                await self.archive.store(desc)
                self.server_descriptors[desc.digest()] = desc
                server_descriptors.append(desc)
        for desc in server_descriptors:
            if desc.extra_info_digest:
                extra_info_descriptor = self.extra_info_descriptors.get(desc.extra_info_digest, None)
                if not extra_info_descriptor:
                    extra_info_descriptor = await self.archive.descriptor(
                        EXTRA_INFO_DESCRIPTOR, desc.extra_info_digest)
                if not extra_info_descriptor:
                    wanted_digests.append(desc.extra_info_digest)
                else:
                    self.extra_info_descriptors[extra_info_descriptor.digest()] = \
                        extra_info_descriptor
        download_tasks.clear()

        # Download extra info descriptors
        while wanted_digests:
            next_batch = [
                wanted_digests.popleft() for _i in range(
                    min(
                        len(wanted_digests),
                        stem.descriptor.remote.MAX_FINGERPRINTS))
            ]
            download_tasks.append(
                self.downloader.descriptor(
                    EXTRA_INFO_DESCRIPTOR, digest=next_batch, endpoint=endpoint))
        await self.downloader.perform_downloads()
        for result in await asyncio.gather(*download_tasks):
            for desc in result:
                self.extra_info_descriptors[desc.digest()] = desc
                await self.archive.store(desc)

        print("All done")


async def scrape(args):
    directory = DirectoryScraper(args.archive_path)
    if not args.no_votes:
        await directory.fetch_votes()
    await directory.fetch_consensus()
