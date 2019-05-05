import datetime
import requests
import sys
import json

from bushel.collector.remote import get_index
from bushel.collector.remote import CollecTorIndex
from bushel.monitoring import nagios_check
from bushel.monitoring import utc_datetime_too_old
from bushel.monitoring import NagiosResponseT

@nagios_check
def check_collector_index_created() -> NagiosResponseT:
    if len(sys.argv) != 2:
        raise RuntimeError("No hostname specified.")
    r = requests.get("https://" + sys.argv[1] + "/index/index.json")
    index = json.loads(r.text)
    index_dt = datetime.datetime.strptime(index["index_created"], "%Y-%m-%d %H:%M")
    dts = {"index_created": index_dt}
    return utc_datetime_too_old(dts, 15*60, 20*60)

def check_collector_latest_recent(name: str, path: str) -> NagiosResponseT:
    if len(sys.argv) != 2:
        raise RuntimeError("No hostname specified.")
    index = get_index(sys.argv[1])
    latest_filename = sorted([x["path"] for x in
        index.raw_directory_contents(path)])[-1]
    latest_dt = datetime.datetime.strptime(latest_filename[:19], "%Y-%m-%d-%H-%M-%S")
    dts = {f"latest_{name}": latest_dt}
    return utc_datetime_too_old(dts, 80*60, 90*60)

@nagios_check
def check_collector_latest_recent_bridge_server_descriptor() -> NagiosResponseT:
    return check_collector_latest_recent("bridge_server_descriptors", "recent/bridge-descriptors/server-descriptors")

@nagios_check
def check_collector_latest_recent_bridge_extra_info() -> NagiosResponseT:
    return check_collector_latest_recent("bridge_extra_info", "recent/bridge-descriptors/extra-infos")

# TODO: The bridge statuses use a different timestamp format
#@nagios_check
#def check_collector_latest_recent_bridge_status() -> NagiosResponseT:
#    return check_collector_latest_recent("bridge_status", "recent/bridge-descriptors/statuses")

@nagios_check
def check_collector_latest_recent_exit_list() -> NagiosResponseT:
    return check_collector_latest_recent("exit_list", "recent/exit-lists")

@nagios_check
def check_collector_latest_recent_relay_consensus() -> NagiosResponseT:
    return check_collector_latest_recent("relay_consensus", "recent/relay-descriptors/consensuses")

@nagios_check
def check_collector_latest_recent_relay_extra_info() -> NagiosResponseT:
    return check_collector_latest_recent("relay_extra_info", "recent/relay-descriptors/extra-infos")

@nagios_check
def check_collector_latest_recent_relay_consensus_microdesc() -> NagiosResponseT:
    return check_collector_latest_recent("relay_consensus_microdesc", "recent/relay-descriptors/microdescs/consensus-microdesc")

@nagios_check
def check_collector_latest_recent_relay_microdesc() -> NagiosResponseT:
    return check_collector_latest_recent("relay_microdesc", "recent/relay-descriptors/microdescs/micro")

@nagios_check
def check_collector_latest_recent_relay_server_descriptor() -> NagiosResponseT:
    return check_collector_latest_recent("relay_server_descriptors", "recent/relay-descriptors/server-descriptors")

@nagios_check
def check_collector_latest_recent_relay_vote() -> NagiosResponseT:
    return check_collector_latest_recent("relay_vote", "recent/relay-descriptors/votes")

# TODO: OnionPerf and webstats use different formats too

if __name__ == "__main__":
    all_checks = [
        check_collector_index_created,
        check_collector_latest_recent_bridge_server_descriptor,
        check_collector_latest_recent_bridge_extra_info,
        check_collector_latest_recent_exit_list,
        check_collector_latest_recent_relay_consensus,
        check_collector_latest_recent_relay_extra_info,
        check_collector_latest_recent_relay_consensus_microdesc,
        check_collector_latest_recent_relay_consensus_microdesc,
        check_collector_latest_recent_relay_server_descriptor,
        check_collector_latest_recent_relay_vote,
    ]
    for check in all_checks:
        try:
            check()
        except SystemExit:
            pass
