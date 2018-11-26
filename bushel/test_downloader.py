import asyncio
import urllib.error
import nose
from nose.tools import assert_equal
from nose.tools import assert_raises

from stem.descriptor import DocumentHandler
from stem.descriptor.remote import get_consensus
from stem.descriptor.networkstatus import NetworkStatusDocumentV3

from bushel import DIRECTORY_AUTHORITIES
from bushel import LOCAL_DIRECTORY_CACHE
from bushel.downloader import DirectoryCacheMode
from bushel.downloader import DirectoryDownloader
from bushel.downloader import UnknownDirectoryCacheModeError
from bushel.downloader import relay_server_descriptors_query_path
from bushel.downloader import relay_extra_info_descriptors_query_path
from bushel.downloader import relay_microdescriptors_query_path


class TestLiveDirectoryDownloader:
    def __init__(self):
        self.has_local_directory_cache = True
        try:
            query = get_consensus(
                endpoints=[LOCAL_DIRECTORY_CACHE],
                retries=0,
                document_handler=DocumentHandler.DOCUMENT)  # pylint: disable=no-member
            consensus = query.run()
            self.downloader = DirectoryDownloader(
                initial_consensus=consensus[0])
        except urllib.error.URLError:
            self.has_local_directory_cache = False
            self.downloader = DirectoryDownloader()

    def test_fetch_consensus(self):
        self.downloader.set_mode(DirectoryCacheMode.TESTING)  # pylint: disable=no-member
        if not self.has_local_directory_cache:
            raise nose.SkipTest(
                f"No local directory cache available at {LOCAL_DIRECTORY_CACHE}"
            )

        async def async_test_part(self):
            consensus = await self.downloader.relay_consensus(flavor="ns")
            assert isinstance(consensus, NetworkStatusDocumentV3)
            assert not consensus.is_microdescriptor

        asyncio.run(async_test_part(self))

    def test_fetch_microdesc_consensus(self):
        self.downloader.set_mode(DirectoryCacheMode.TESTING)  # pylint: disable=no-member
        if not self.has_local_directory_cache:
            raise nose.SkipTest(
                f"No local directory cache available at {LOCAL_DIRECTORY_CACHE}"
            )

        async def async_test_part(self):
            consensus = await self.downloader.relay_consensus(
                flavor="microdesc")
            assert isinstance(consensus, NetworkStatusDocumentV3)
            assert consensus.is_microdescriptor

        asyncio.run(async_test_part(self))

    def test_mode_testing(self):
        self.downloader.set_mode(DirectoryCacheMode.TESTING)  # pylint: disable=no-member
        assert len(self.downloader.endpoints) == 1
        assert len(self.downloader.extra_info_endpoints) == 1
        assert_equal(self.downloader.endpoints[0], LOCAL_DIRECTORY_CACHE)
        assert_equal(self.downloader.extra_info_endpoints[0],
                     LOCAL_DIRECTORY_CACHE)

    def test_mode_directory_cache(self):
        self.downloader.set_mode(DirectoryCacheMode.DIRECTORY_CACHE)  # pylint: disable=no-member
        authorities = {a.dir_port for a in DIRECTORY_AUTHORITIES}
        endpoints = set(self.downloader.endpoints)
        extra_info_endpoints = set(self.downloader.extra_info_endpoints)
        assert authorities <= extra_info_endpoints
        assert extra_info_endpoints <= endpoints

    def test_mode_client(self):
        self.downloader.set_mode(DirectoryCacheMode.CLIENT)  # pylint: disable=no-member
        authorities = {a.dir_port for a in DIRECTORY_AUTHORITIES}
        endpoints = set(self.downloader.endpoints)
        extra_info_endpoints = set(self.downloader.extra_info_endpoints)
        assert authorities <= extra_info_endpoints
        assert extra_info_endpoints <= endpoints

    def test_mode_integer(self):
        with assert_raises(TypeError):
            self.downloader.set_mode(1)

    def test_mode_unknown(self):
        with assert_raises(UnknownDirectoryCacheModeError):
            self.downloader.set_mode("unknown")

def test_relay_server_descriptors_query_path():
    expected = [
        ([
            "A94A07B201598D847105AE5FCD5BC3AB10124389",
            "B38974987323394795879383ABEF4893BD4895A8"
        ], ("/tor/server/d/A94A07B201598D847105AE5FCD5BC3AB10124389+"
            "B38974987323394795879383ABEF4893BD4895A8")),
        ([
            "a94a07b201598d847105ae5fcd5bc3ab10124389",
            "B38974987323394795879383ABEF4893BD4895A8"
        ], ("/tor/server/d/A94A07B201598D847105AE5FCD5BC3AB10124389+"
            "B38974987323394795879383ABEF4893BD4895A8")),
        ([
            "a94a07b201598d847105ae5fcd5bc3ab10124389",
            "b38974987323394795879383abef4893bd4895a8"
        ], ("/tor/server/d/A94A07B201598D847105AE5FCD5BC3AB10124389+"
            "B38974987323394795879383ABEF4893BD4895A8")),
        (["A94A07B201598D847105AE5FCD5BC3AB10124389"],
         "/tor/server/d/A94A07B201598D847105AE5FCD5BC3AB10124389"),
    ]
    for case in expected:
        assert_equal(relay_server_descriptors_query_path(case[0]), case[1])


def test_relay_extra_info_descriptors_query_path():
    expected = [
        ([
            "A94A07B201598D847105AE5FCD5BC3AB10124389",
            "B38974987323394795879383ABEF4893BD4895A8"
        ], ("/tor/extra/d/A94A07B201598D847105AE5FCD5BC3AB10124389+"
            "B38974987323394795879383ABEF4893BD4895A8")),
        ([
            "a94a07b201598d847105ae5fcd5bc3ab10124389",
            "B38974987323394795879383ABEF4893BD4895A8"
        ], ("/tor/extra/d/A94A07B201598D847105AE5FCD5BC3AB10124389+"
            "B38974987323394795879383ABEF4893BD4895A8")),
        ([
            "a94a07b201598d847105ae5fcd5bc3ab10124389",
            "b38974987323394795879383abef4893bd4895a8"
        ], ("/tor/extra/d/A94A07B201598D847105AE5FCD5BC3AB10124389+"
            "B38974987323394795879383ABEF4893BD4895A8")),
        (["A94A07B201598D847105AE5FCD5BC3AB10124389"],
         "/tor/extra/d/A94A07B201598D847105AE5FCD5BC3AB10124389"),
    ]
    for case in expected:
        assert_equal(relay_extra_info_descriptors_query_path(case[0]), case[1])


def test_relay_microdescriptors_descriptors_query_path():
    expected = [
        ([
            "Z62HG1C9PLIVs8jLi1guO48rzPdcq6tFTLi5s27Zy4U",
            "FkiLuQJe/Gqp4xsHfheh+G42TSJ77AarHOGrjazj0Q0"
        ], ("/tor/micro/d/Z62HG1C9PLIVs8jLi1guO48rzPdcq6tFTLi5s27Zy4U-"
            "FkiLuQJe/Gqp4xsHfheh+G42TSJ77AarHOGrjazj0Q0")),
        (["Z62HG1C9PLIVs8jLi1guO48rzPdcq6tFTLi5s27Zy4U"],
         "/tor/micro/d/Z62HG1C9PLIVs8jLi1guO48rzPdcq6tFTLi5s27Zy4U"),
    ]
    for case in expected:
        assert_equal(relay_microdescriptors_query_path(case[0]), case[1])


# TODO: Test fingerprint/digest batching
# TODO: Test exhaustive retry mechanism
# TODO: Test valid-after time rejection
