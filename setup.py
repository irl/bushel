#!/usr/bin/env python3.7

from setuptools import setup
from setuptools import find_packages

#with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
#    long_description = f.read()

with open('requirements.txt') as f:
    install_requires = f.read().splitlines()

setup(name='bushel',
    version='0.0.0a0',
    description=('A tool for fetching, inspecting and archiving Tor '
                 'directory protocol descriptors'),
    #long_description=long_description,
    author='Iain R. Learmonth',
    author_email="irl@torproject.org",
    license='MIT',
    url='https://github.com/irl/bushel',
    keywords='archive collector directory measurement metrics relay tor',
    classifiers=[
        'Development Status :: 1 - Planning',
        'Environment :: Console',
        'Framework :: AsyncIO',
        'Intended Audience :: Science/Research',
        'Topic :: Communications',
        'Topic :: Internet',
        'Topic :: Internet :: Log Analysis',
        'Topic :: Scientific/Engineering :: Information Analysis',
        'Topic :: System :: Archiving',
        'Topic :: System :: Networking :: Monitoring',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: Implementation :: CPython',
    ],
    packages=find_packages(exclude=['relay_descriptors', 'doc']),
    entry_points={
        'console_scripts': [
            'bushel=bushel.run:main',
            'check_collector_index_created=bushel.monitoring.collector:check_collector_index_created',
            'check_collector_latest_recent_bridge_server_descriptor=bushel.monitoring.collector:check_collector_latest_recent_bridge_server_descriptor',
            'check_collector_latest_recent_bridge_extra_info=bushel.monitoring.collector:check_collector_latest_recent_bridge_extra_info',
            'check_collector_latest_recent_exit_list=bushel.monitoring.collector:check_collector_latest_recent_exit_list',
            'check_collector_latest_recent_relay_consensus=bushel.monitoring.collector:check_collector_latest_recent_relay_consensus',
            'check_collector_latest_recent_relay_extra_info=bushel.monitoring.collector:check_collector_latest_recent_relay_extra_info',
            'check_collector_latest_recent_relay_consensus_microdesc=bushel.monitoring.collector:check_collector_latest_recent_relay_consensus_microdesc',
            'check_collector_latest_recent_relay_microdesc=bushel.monitoring.collector:check_collector_latest_recent_relay_consensus_microdesc',
            'check_collector_latest_recent_relay_server_descriptor=bushel.monitoring.collector:check_collector_latest_recent_relay_server_descriptor',
            'check_collector_latest_recent_relay_vote=bushel.monitoring.collector:check_collector_latest_recent_relay_vote',
        ],
    },
    test_suite = 'nose.collector',
)
