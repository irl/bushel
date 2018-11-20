import asyncio
import argparse
import logging

from bushel.scrub import scrub
from bushel.scraper import scrape

logging.basicConfig()

def main():
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
    parser.add_argument("--verbose", action="store_true", help="Enhanced logging")
    subparsers = parser.add_subparsers(help="Subcommands")

    parser_scrape = subparsers.add_parser(
        "scrape",
        help="Recursively download all documents referenced by the latest consensus"
    )
    parser_scrape.add_argument("--client", help="Download in client mode", action="store_true")
    parser_scrape.add_argument("--archive-path", help="Alternative path to the archive", default=".")
    parser_scrape.set_defaults(coro=scrape)

    parser_scrub = subparsers.add_parser(
        "scrub", help="Check for missing documents in the filesystem storage")
    parser_scrub.add_argument(
        "path", help="Path to consensus(es) to use as starting points")
    parser_scrub.add_argument("--legacy-archive", help="Strict CollecTor File Structure Protocol mode", default=False, action="store_true")
    parser_scrub.add_argument("--ignore-extra-info", help="Ignore references to extra-info descriptors", default=False, action="store_true")
    parser_scrub.set_defaults(coro=scrub)

    args = parser.parse_args()
    logging.getLogger("bushel").setLevel(
        logging.DEBUG if args.verbose else logging.INFO
    )
    if vars(args).get("func"):
        args.func(args)
    elif vars(args).get("coro"):
        asyncio.run(args.coro(args))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
