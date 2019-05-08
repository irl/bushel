#!/usr/bin/env zsh

/usr/bin/python3.7 -m pylint bushel nagios/*
/usr/bin/python3.7 -m mypy --ignore-missing-imports bushel nagios/*
/usr/bin/python3.7 -m nose --with-doctest bushel
