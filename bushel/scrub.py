import os
import stem.descriptor.reader
from stem.descriptor import DocumentHandler
from stem.descriptor import parse_file
from stem.util import term


def scrub(path):
    if path is None:
        path = "relay-descriptors/consensuses"
    with stem.descriptor.reader.DescriptorReader(
            [path], document_handler=DocumentHandler.DOCUMENT) as reader: # pylint: disable=no-member
        for descriptor in reader:
            va = descriptor.valid_after
            print(
                term.format(f"Found a consensus, valid-after {va}", 'bg_red'))
            if descriptor.get_unrecognized_lines():
                print(f"WARNING: Consensus {va} contained unrecognized lines "
                      "that stem did not parse.")
            for status in descriptor.routers.values():
                digest = status.digest.lower()
                path = os.path.join(
                    "relay-descriptors", "server-descriptors",
                    f"server-descriptors-{va.year}-{va.month}", f"{digest[0]}",
                    f"{digest[1]}", f"{digest}")
                # TODO: Check last month
                try:
                    server = next(
                        parse_file(
                            path, descriptor_type="server-descriptor 1.0"))
                    if server.get_unrecognized_lines():
                        print(f"WARNING: Server descriptor {digest} contained "
                              "unrecognized lines that stem did not parse.")
                except FileNotFoundError:
                    print("Could not find server descriptor for "
                          f"{status.fingerprint} with digest {digest}.")
                    print("https://metrics.torproject.org/rs.html#details/"
                          f"{status.fingerprint}")
                    continue
                if server.extra_info_digest:
                    digest = server.extra_info_digest.lower()
                    path = os.path.join("relay-descriptors", "extra-infos",
                                        f"extra-infos-{va.year}-{va.month}",
                                        f"{digest[0]}", f"{digest[1]}",
                                        f"{digest}")
                    try:
                        next(
                            parse_file(path, descriptor_type="extra-info 1.0"))
                        if server.get_unrecognized_lines():
                            print(f"WARNING: Extra info descriptor {digest} "
                                  "contained unrecognized lines that stem did "
                                  "not parse.")
                    except FileNotFoundError:
                        print("Could not find extra info descriptor for "
                              f"{status.fingerprint} with digest {digest}.")
                        print("https://metrics.torproject.org/rs.html#details/"
                              f"{status.fingerprint}")
                        continue
