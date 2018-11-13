import asyncio
import argparse
import logging

from bushel.scrub import scrub
from bushel.scraper import scrape

logging.basicConfig()


class SubcommandHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def _format_action(self, action):
        parts = super()._format_action(action)
        if action.nargs == argparse.PARSER:
            #parts = "\n".join([line for line in parts.split("\n")[1:]])
            parts += "\n\nOnion safely!"
        return parts


parser = argparse.ArgumentParser(
    description='A bushel of onions is 57 lbs',
    formatter_class=SubcommandHelpFormatter)
subparsers = parser.add_subparsers(help="Subcommands")

parser_scrape = subparsers.add_parser(
    "scrape",
    help="Recursively download all documents referenced by the latest consensus"
)
parser_scrape.set_defaults(coro=scrape)

parser_scrub = subparsers.add_parser(
    "scrub", help="Check for missing documents in the filesystem storage")
parser_scrub.add_argument(
    "path", help="Path to consensus(es) to use as starting points")
parser_scrub.set_defaults(func=scrub)

if __name__ == "__main__":
    args = parser.parse_args()
    if vars(args).get("func"):
        args.func(args.path)
    elif vars(args).get("coro"):
        asyncio.run(args.coro())
    else:
        parser.print_help()
