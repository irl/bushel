import asyncio
import collections
import datetime
import logging
import random

import stem

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel import DirectoryCacheMode
from bushel.archive import DirectoryArchive
from bushel.downloader import DirectoryDownloader

LOG = logging.getLogger('')

class DirectoryCache:
    def __init__(self, archive_path):
        self.descriptors = {}
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
        consensus = await self.archive.consensus(valid_after)
        if not consensus:
            consensus = await self.downloader.consensus()
            if consensus:
                await self.archive.store(consensus)
        return consensus

    async def vote(self, v3ident, digest="*", valid_after=None):
        vote = await self.archive.vote(v3ident, digest="*", valid_after=valid_after)
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

    async def descriptor(self, doctype, digest=None, published_hint=None, endpoint=None):
        if isinstance(digest, str):
            descriptor = self._cached_descriptor(doctype, digest)
            if descriptor:
                return descriptor
            if doctype is SERVER_DESCRIPTOR:
                descriptor = await self.archive.relay_server_descriptor(
                    digest, published_hint=published_hint)
            else:
                descriptor = await self.archive.relay_extra_info_descriptor(
                    digest, published_hint=published_hint)
            if not descriptor:
                descriptor = await self.downloader.descriptor(
                    doctype, digest=digest, endpoint=endpoint)
                if descriptor:
                    await self.archive.store(descriptor)
            if descriptor:
                if not self.descriptors.get(doctype):
                    self.descriptors[doctype] = {}
                self.descriptors[doctype][digest] = descriptor
            return descriptor
        else:
            results = await asyncio.gather(*[self.descriptor(
                                                 doctype, d, published_hint, endpoint)
                                             for d in digest])
            return [r for r in results if r]
