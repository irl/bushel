import datetime
import re

from documents.directory import DirectoryDocument
from documents.directory import expect_arguments
from documents.directory import parse_timestamp


class NetworkStatusConsensus(DirectoryDocument):

    def __init__(self, raw_content):
        super().__init__(raw_content)
        self.PARSE_FUNCTIONS = {
            "network-status-version": self.parse_network_status_version,
            "vote-status": self.parse_vote_status,
            "consensus-method": self.parse_consensus_method,
            "valid-after": self.parse_valid_after,
            "fresh-until": self.parse_fresh_until,
            "valid-until": self.parse_valid_until,
            "voting-delay": self.parse_voting_delay,
            "client-versions": self.parse_client_versions,
            "server-versions": self.parse_server_versions,
            "recommended-client-protocols": self.parse_recommended_client_protocols,
            "recommended-relay-protocols": self.parse_recommended_relay_protocols,
        }

    @expect_arguments(1, 1, True)
    def parse_network_status_version(self, item):
        self.network_status_version = item.arguments[0]

    @expect_arguments(1, 1, True)
    def parse_vote_status(self, item):
        self.vote_status = item.arguments[0]

    @expect_arguments(1, 1, True)
    def parse_consensus_method(self, item):
        self.consensus_method = item.arguments[0]

    @expect_arguments(2, 2, True)
    def parse_valid_after(self, item):
        self.valid_after = parse_timestamp(item)

    @expect_arguments(2, 2, True)
    def parse_fresh_until(self, item):
        self.fresh_until = parse_timestamp(item)

    @expect_arguments(2, 2, True)
    def parse_valid_until(self, item):
        self.valid_until = parse_timestamp(item)

    @expect_arguments(2, 2, True)
    def parse_voting_delay(self, item):
        self.vote_seconds, self.dist_seconds = item.arguments

    @expect_arguments(1, 1, True)
    def parse_client_versions(self, item):
        self.client_versions = item.arguments[0].split(",")

    @expect_arguments(1, 1, True)
    def parse_server_versions(self, item):
        self.server_versions = item.arguments[0].split(",")

    @expect_arguments(1, 12, False)
    def parse_known_flags(self, item):
        self.known_flags = item.arguments

    @expect_arguments(1, 9, False)
    def parse_recommended_client_protocols(self, item):
        self.recommended_client_protocols = {x[0]: x[1] for x in [y.split("=") for y in item.arguments]}

    @expect_arguments(1, 9, False)
    def parse_recommended_relay_protocols(self, item):
        self.recommended_relay_protocols = {x[0]: x[1] for x in [y.split("=") for y in item.arguments]}
