# RsyncHelper
Python wrapper script for rsync

## Work in Progress

The goal of this project was to create a wrapper for rsync in python that would allow reporting via logfile and / or email of a regular sync job, most likely run from cron or systemd. This is obviously linux only.

## Features

- Configuration via config file
- Ability to send reports via smtp / smtp w/tls or via log file.
- Log file rotation (TODO)
- Ability to check and attempt a mount point prior to sync

## Config file format

This is basically .ini style format, with elements as below:

(TODO)
