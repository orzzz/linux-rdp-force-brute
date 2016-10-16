#！/bin/sh

path=`pwd`
apt-get -y update &&
apt-get -y install build-essential && 
gcc s.c -lpthread -o s &&
apt-get -y install libssl-dev libssh-dev libidn11-dev libpcre3-dev libgtk2.0-dev libmysqlclient-dev libpq-dev libsvn-dev firebird2.1-dev libncp-dev libncurses5-dev &&
cd /tmp
mkdir hydra
cd hydra
wget http://www.thc.org/releases/hydra-8.3.tar.gz &&
tar zxf hydra-8.3.tar.gz &&
cd hydra-8.3
./configure &&
make && make install
cd $path
touch ipranges.txt
chmod +x hydra.sh 
chmod +x rdpbrute.sh
clear &&
echo "Install Complete!"
