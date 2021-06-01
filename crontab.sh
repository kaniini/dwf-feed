#!/bin/sh

. prod/bin/activate

cd ~/dwflist
git pull

cd ~/dwf-feed
python3 dwf-feed.py ../dwflist
