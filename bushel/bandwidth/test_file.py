from bushel.bandwidth.file import BandwidthFile

example_version_100 = b"""1523911758
node_id=$68A483E05A2ABDCA6DA5A3EF8DB5177638A27F80 bw=760 nick=Test measured_at=1523911725 updated_at=1523911725 pid_error=4.11374090719 pid_error_sum=4.11374090719 pid_bw=57136645 pid_delta=2.12168374577 circ_fail=0.2 scanner=/filepath
node_id=$96C15995F30895689291F455587BD94CA427B6FC bw=189 nick=Test2 measured_at=1523911623 updated_at=1523911623 pid_error=3.96703337994 pid_error_sum=3.96703337994 pid_bw=47422125 pid_delta=2.65469736988 circ_fail=0.0 scanner=/filepath
"""

def test_example_version_100():
    for line in BandwidthFile(example_version_100).lines():
        pass

example_sbws_010 = b"""1523911758
version=1.1.0
software=sbws
software_version=0.1.0
latest_bandwidth=2018-04-16T20:49:18
file_created=2018-04-16T21:49:18
generator_started=2018-04-16T15:13:25
earliest_bandwidth=2018-04-16T15:13:26
====
bw=380 error_circ=0 error_misc=0 error_stream=1 master_key_ed25519=YaqV4vbvPYKucElk297eVdNArDz9HtIwUoIeo0+cVIpQ nick=Test node_id=$68A483E05A2ABDCA6DA5A3EF8DB5177638A27F80 rtt=380 success=1 time=2018-05-08T16:13:26
bw=189 error_circ=0 error_misc=0 error_stream=0 master_key_ed25519=a6a+dZadrQBtfSbmQkP7j2ardCmLnm5NJ4ZzkvDxbo0I nick=Test2 node_id=$96C15995F30895689291F455587BD94CA427B6FC rtt=378 success=1 time=2018-05-08T16:13:36
"""

def test_example_sbws_010():
    for line in BandwidthFile(example_sbws_010).lines():
        pass

example_sbws_103 = b"""1523911758
version=1.2.0
latest_bandwidth=2018-04-16T20:49:18
file_created=2018-04-16T21:49:18
generator_started=2018-04-16T15:13:25
earliest_bandwidth=2018-04-16T15:13:26
minimum_number_eligible_relays=3862
minimum_percent_eligible_relays=60
number_consensus_relays=6436
number_eligible_relays=6000
percent_eligible_relays=93
software=sbws
software_version=1.0.3
=====
bw=38000 bw_mean=1127824 bw_median=1180062 desc_avg_bw=1073741824 desc_obs_bw_last=17230879 desc_obs_bw_mean=14732306 error_circ=0 error_misc=0 error_stream=1 master_key_ed25519=YaqV4vbvPYKucElk297eVdNArDz9HtIwUoIeo0+cVIpQ nick=Test node_id=$68A483E05A2ABDCA6DA5A3EF8DB5177638A27F80 rtt=380 success=1 time=2018-05-08T16:13:26
bw=1 bw_mean=199162 bw_median=185675 desc_avg_bw=409600 desc_obs_bw_last=836165 desc_obs_bw_mean=858030 error_circ=0 error_misc=0 error_stream=0 master_key_ed25519=a6a+dZadrQBtfSbmQkP7j2ardCmLnm5NJ4ZzkvDxbo0I nick=Test2 node_id=$96C15995F30895689291F455587BD94CA427B6FC rtt=378 success=1 time=2018-05-08T16:13:36
"""

def test_example_sbws_103():
    for line in BandwidthFile(example_sbws_103).lines():
        pass

example_not_enough_eligible = b"""1540496079
version=1.2.0
earliest_bandwidth=2018-10-20T19:35:52
file_created=2018-10-25T19:35:03
generator_started=2018-10-25T11:42:56
latest_bandwidth=2018-10-25T19:34:39
minimum_number_eligible_relays=3862
minimum_percent_eligible_relays=60
number_consensus_relays=6436
number_eligible_relays=2960
percent_eligible_relays=46
software=sbws
software_version=1.0.3
=====
"""

def test_example_not_enough_eligible():
    for line in BandwidthFile(example_sbws_104).lines():
        pass

example_sbws_104 = b"""1523911758
version=1.3.0
latest_bandwidth=2018-04-16T20:49:18
destinations_countries=TH,ZZ
file_created=2018-04-16T21:49:18
generator_started=2018-04-16T15:13:25
earliest_bandwidth=2018-04-16T15:13:26
minimum_number_eligible_relays=3862
minimum_percent_eligible_relays=60
number_consensus_relays=6436
number_eligible_relays=6000
percent_eligible_relays=93
scanner_country=SN
software=sbws
software_version=1.0.4
=====
"""

def test_example_sbws_104():
    for line in BandwidthFile(example_sbws_104).lines():
        pass

example_sbws_110 = b"""1523911758
version=1.4.0
latest_bandwidth=2018-04-16T20:49:18
destinations_countries=TH,ZZ
file_created=2018-04-16T21:49:18
generator_started=2018-04-16T15:13:25
earliest_bandwidth=2018-04-16T15:13:26
minimum_number_eligible_relays=3862
minimum_percent_eligible_relays=60
number_consensus_relays=6436
number_eligible_relays=6000
percent_eligible_relays=93
recent_measurement_attempt_count=6243
recent_measurement_failure_count=732
recent_measurements_excluded_error_count=969
recent_measurements_excluded_few_count=3946
recent_measurements_excluded_near_count=90
recent_measurements_excluded_old_count=0
recent_priority_list_count=20
recent_priority_relay_count=6243
scanner_country=SN
software=sbws
software_version=1.1.0
time_to_report_half_network=57273
=====
bw=1 error_circ=1 error_destination=0 error_misc=0 error_second_relay=0 error_stream=0 master_key_ed25519=J3HQ24kOQWac3L1xlFLp7gY91qkb5NuKxjj1BhDi+m8 nick=snap269 node_id=$DC4D609F95A52614D1E69C752168AF1FCAE0B05F relay_recent_measurement_attempt_count=3 relay_recent_measurements_excluded_error_count=1 relay_recent_measurements_excluded_near_count=3 relay_recent_consensus_count=3 relay_recent_priority_list_count=3 success=3 time=2019-03-16T18:20:57 unmeasured=1 vote=0
bw=1 error_circ=0 error_destination=0 error_misc=0 error_second_relay=0 error_stream=2 master_key_ed25519=h6ZB1E1yBFWIMloUm9IWwjgaPXEpL5cUbuoQDgdSDKg nick=relay node_id=$C4544F9E209A9A9B99591D548B3E2822236C0503 relay_recent_measurement_attempt_count=3 relay_recent_measurements_excluded_error_count=2 relay_recent_measurements_excluded_few_count=1 relay_recent_consensus_count=3 relay_recent_priority_list_count=3 success=1 time=2019-03-17T06:50:58 unmeasured=1 vote=0
"""

def test_example_sbws_110():
    for line in BandwidthFile(example_sbws_110).lines():
        pass
