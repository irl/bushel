#!/usr/bin/env python3.7

from distutils.core import setup

setup(name='bushel',
      version='0.0.0a',
      description='A tool for fetching, inspecting and archiving Tor directory protocol descriptors',
      author='Iain R. Learmonth',
      url='https://github.com/irl/bushel',
      packages=['bushel'],
      entry_points={
          'console_scripts': [
              'bushel = bushel.__main__:main'
          ]
      },
)
