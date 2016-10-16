#! /bin/sh

port=$1

rm -f hydra.restore >/dev/null 2>&1
for iprange in $(cat ipranges.txt)
        do
                ./s $iprange $port /save
                cat Result.txt |grep $port | cut -d " " -f 1 >> ip.txt
                rm -f Result.txt
                ./hydra.sh
                rm -f hydra.restore
                rm -f ip.txt >/dev/null 2>&1
done
