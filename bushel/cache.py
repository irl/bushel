import asyncio
import datetime
import logging
import random
import sys
from collections import defaultdict

import stem

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel import DirectoryCacheMode
from bushel.archive import DirectoryArchive
from bushel.downloader import DirectoryDownloader

LOG = logging.getLogger('')

class DirectoryCache:
    def __init__(self, archive_path):
        self.descriptors = defaultdict(dict)
        self.archive = DirectoryArchive(archive_path)
        self.downloader = DirectoryDownloader()
        self.downloader.descriptor_cache = self._cached_descriptor # TODO: Do something more sensible

    def set_mode(self, directory_cache_mode):
        self.downloader.set_mode(directory_cache_mode)

    async def consensus(self, valid_after=None):
        """
        Returns the consensus with the specified valid_after time if available
        from the archive or a directory server.

        :param datetime valid_after: The valid_after time for the requested
                                     consensus. If *None* then the latest
                                     consensus will be retrieved.
        """
        consensus = await self.archive.relay_consensus(valid_after)
        if not consensus:
            consensus = await self.downloader.consensus()
            if consensus:
                await self.archive.store(consensus)
        return consensus

    async def vote(self, v3ident, digest="*", valid_after=None):
        vote = await self.archive.relay_vote(v3ident, digest="*", valid_after=valid_after)
        if vote is None:
            vote = await self.downloader.vote(digest=digest)
            if vote is None:
                return
            await self.archive.store(vote)
        return vote

    def _cached_descriptor(self, doctype, digest):
        if doctype in self.descriptors:
            if digest in self.descriptors[doctype]:
                return self.descriptors[doctype][digest]

    async def relay_server_descriptors(self, digests, published_hint=None):
        descriptors = []
        for digest in digests:
            descriptor = self._cached_descriptor(SERVER_DESCRIPTOR, digest)
            if descriptor:
                descriptors.append(descriptor)
                digests.remove(descriptor.digest())
        if not digests:
            return descriptors
        archived_descriptors = await self.archive.relay_server_descriptors(
            digests, published_hint=published_hint)
        for descriptor in archived_descriptors:
            digests.remove(descriptor.digest())
        descriptors += archived_descriptors
        if digests:
            downloaded_descriptors = await self.downloader.relay_server_descriptors(
                digests, published_hint=published_hint)
            if downloaded_descriptors:
                descriptors += downloaded_descriptors
                for descriptor in downloaded_descriptors:
                    await self.archive.store(descriptor)
        for descriptor in descriptors:
            self.descriptors[SERVER_DESCRIPTOR][digest] = descriptor
        return descriptors

    async def relay_extra_info_descriptors(self, digests, published_hint=None):
        descriptors = []
        for digest in digests:
            descriptor = self._cached_descriptor(EXTRA_INFO_DESCRIPTOR, digest)
            if descriptor:
                descriptors.append(descriptor)
                digests.remove(descriptor.digest())
        if not digests:
            return descriptors
        archived_descriptors = await self.archive.relay_extra_info_descriptors(
            digests, published_hint=published_hint)
        for descriptor in archived_descriptors:
            digests.remove(descriptor.digest())
        descriptors += archived_descriptors
        if digests:
            downloaded_descriptors = await self.downloader.relay_extra_info_descriptors(
                digests, published_hint=published_hint)
            if downloaded_descriptors:
                descriptors += downloaded_descriptors
                for descriptor in downloaded_descriptors:
                    await self.archive.store(descriptor)
        for descriptor in descriptors:
            self.descriptors[EXTRA_INFO_DESCRIPTOR][digest] = descriptor
        return descriptors
