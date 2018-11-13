#!/usr/bin/env zsh

/usr/bin/python3.7 -m pylint bushel/*.py
/usr/bin/python3.7 -m nose --with-doctest bushel
