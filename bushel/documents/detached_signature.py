import datetime
import logging
import re
from documents.directory import DirectoryDocument
from documents.directory import parse_timestamp

class DetachedSignature(DirectoryDocument):

    def __init__(self, raw_content):
        self.PARSE_FUNCTIONS = {
            "consensus-digest": self.parse_consensus_digest,
            "valid-after": self.parse_valid_after,
            "fresh-until": self.parse_fresh_until,
            "valid-until": self.parse_valid_until,
        }
        super().__init__(raw_content)

    def parse_consensus_digest(self, item):
        self.consensus_digest = item.arguments[0]

    def parse_valid_after(self, item):
        self.valid_after = parse_timestamp(item)

    def parse_fresh_until(self, item):
        self.fresh_until = item.arguments[0]

    def parse_valid_until(self, item):
        self.valid_until = item.arguments[0]

    def parse(self):
        for item in self.items():
            print(item.keyword)
            if item.keyword in self.PARSE_FUNCTIONS:
                self.PARSE_FUNCTIONS[item.keyword](item)

    def validate(self):
        pass
