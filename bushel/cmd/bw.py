import sys

from bushel import PluggableCommand
from bushel.bandwidth.file import BandwidthFile

def cmd_bw(args):
    sys.stdout.buffer.write(b"not implemented")

def cmd_tokenize(args):
    data = sys.stdin.buffer.read()
    document = BandwidthFile(data)
    for token in document.tokenize():
        print(token)

def cmd_lines(args):
    data = sys.stdin.buffer.read()
    document = BandwidthFile(data)
    allowed_errors = []
    if args.forgive:
        for allowed_error in args.forgive.split(","):
            allowed_errors.append(DirectoryDocumentItemError(allowed_error))
    for item in document.lines(allowed_errors=allowed_errors):
        print(item)


class BwCommand(PluggableCommand):
    @staticmethod
    def register_subparser(subparsers):
        parser_bw = subparsers.add_parser(
            "bw", help="Tor Bandwidth Scanner commands")
        bw_subparsers = parser_bw.add_subparsers(help="Subcommands")
        parser_bw.set_defaults(func=cmd_bw)

        parser_itemize = bw_subparsers.add_parser(
            "tokenize", help="Tokenize a bandwidth file")
        parser_itemize.set_defaults(func=cmd_tokenize)

        parser_lines = bw_subparsers.add_parser(
            "lines", help="Parse lines of a bandwidth file")
        parser_lines.add_argument("--forgive", metavar="ERRORS",
                                    help=("List of errors to forgive seperated "
                                          "by commas"))
        parser_lines.set_defaults(func=cmd_lines)
