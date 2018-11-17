import asyncio
import functools
import io
import json
import logging
import os

import aiofiles

import stem
import stem.descriptor.reader
from stem.descriptor import DocumentHandler
from stem.descriptor import parse_file

from bushel import SERVER_DESCRIPTOR
from bushel import EXTRA_INFO_DESCRIPTOR
from bushel.archive import EXTRA_INFO_DESCRIPTOR_MARKER
from bushel.archive import SERVER_DESCRIPTOR_MARKER
from bushel.archive import DirectoryArchive

LOG = logging.getLogger("scrub")

def print_stats(stats):
    print(f"{stats['valid_after']},"
          f"{stats['server_referenced']},"
          f"{stats['server_descriptor']},"
          f"{stats['directory_cache']},"
          f"{stats['directory_cache_dir_port']},"
          f"{stats['extra_info_cache']},"
          f"{stats['extra_info_cache_dir_port']},"
          f"{stats['extra_info_referenced']},"
          f"{stats['extra_info_descriptor']}",
          flush=True)

class DirectoryArchiveScrubber:

    def __init__(self, archive):
        self.archive = archive

    async def scrub(self, consensus_path, ignore_extra_info=False):
        with stem.descriptor.reader.DescriptorReader(
                [consensus_path], buffer_size=1,
                document_handler=DocumentHandler.DOCUMENT) as reader: # pylint: disable=no-member
            for descriptor in reader:
                valid_after = descriptor.valid_after
                stats = {"valid_after": valid_after.isoformat(),
                         "server_referenced": 0,
                         "server_descriptor": 0,
                         "directory_cache": 0,
                         "directory_cache_dir_port": 0,
                         "extra_info_cache": 0,
                         "extra_info_cache_dir_port": 0,
                         "extra_info_referenced": 0,
                         "extra_info_descriptor": 0}
                LOG.info(f"Found a consensus, valid-after {valid_after}")
                if descriptor.get_unrecognized_lines():
                    LOG.warning(f"WARNING: Consensus {valid_after} contained unrecognized lines "
                                "that stem did not parse.")
                status_stats = []
                max_concurrency_lock = asyncio.BoundedSemaphore(50)
                for status in descriptor.routers.values():
                    stats["server_referenced"] += 1
                    status_stats.append(self.scrub_status_entry(valid_after,
                                                                status,
                                                                ignore_extra_info,
                                                                max_concurrency_lock))
                for result in await asyncio.gather(*status_stats):
                    for key in result:
                        stats[key] += result[key]
                print_stats(stats)

    async def scrub_status_entry(self, valid_after, status, ignore_extra_info, max_concurrency_lock):
        stats = {
            "directory_cache": 0,
            "directory_cache_dir_port": 0,
            "server_descriptor": 0,
            "extra_info_cache": 0,
            "extra_info_cache_dir_port": 0,
            "extra_info_referenced": 0,
            "extra_info_descriptor": 0,
        }
        if stem.Flag.V2DIR in status.flags:
            stats["directory_cache"] += 1
            if status.dir_port is not None:
                stats["directory_cache_dir_port"] += 1
        digest = status.digest.lower()
        server = await self.archive.descriptor(
            SERVER_DESCRIPTOR,
            digest,
            published_hint=valid_after)
        if server:
            stats["server_descriptor"] += 1
            LOG.debug(f"Successfully loaded server descriptor for {server.fingerprint}.")
            if server.get_unrecognized_lines():
                LOG.warning(f"WARNING: Server descriptor {digest} contained "
                      "unrecognized lines that stem did not parse.")
            if stem.Flag.V2DIR in status.flags and server.extra_info_cache:
                stats["extra_info_cache"] += 1
                if server.dir_port is not None:
                    stats["extra_info_cache_dir_port"] += 1
            if not ignore_extra_info and server.extra_info_digest:
                stats["extra_info_referenced"] += 1
                digest = server.extra_info_digest.lower()
                extra_info = await self.archive.descriptor(
                    EXTRA_INFO_DESCRIPTOR,
                    digest,
                    published_hint=valid_after)
                if extra_info:
                    LOG.debug(f"Successfully loaded extra-info descriptor for {server.fingerprint}.")
                    stats["extra_info_descriptor"] += 1
                    if extra_info.get_unrecognized_lines():
                        LOG.warning(f"WARNING: Extra info descriptor {digest} "
                                  "contained unrecognized lines that stem did "
                                  "not parse.")
                else:
                    LOG.warning("Could not find extra info descriptor for "
                          f"{status.fingerprint} with digest {digest}."
                          "https://metrics.torproject.org/rs.html#details/"
                          f"{status.fingerprint}")
        else:
            LOG.warning("Could not find extra info descriptor for "
                          f"{status.fingerprint} with digest {digest}."
                          "https://metrics.torproject.org/rs.html#details/"
                          f"{status.fingerprint}")
        return stats

async def scrub(args):
    archive = DirectoryArchive(".", legacy_archive=args.legacy_archive)
    scrubber = DirectoryArchiveScrubber(archive)
    await scrubber.scrub(args.path, args.ignore_extra_info)
