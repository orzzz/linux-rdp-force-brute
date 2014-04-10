#！/bin/sh

apt-get -y update &&
apt-get -y install build-essential && 
gcc s.c -lpthread -o s &&
mv s /usr/sbin/
