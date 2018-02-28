#!/bin/bash
res=$(lsb_release -a)
echo $res
xen='xenial'
if [[ $res == *$xen* ]]
then
   echo "ubuntu16.04"
   mv /etc/apt/sources.list /etc/apt/sources.list.back16.04
   mv ubuntu16.04.source /etc/apt/sources.list
else
   echo "ubuntu14.04"
   mv /etc/apt/sources.list /etc/apt/sources.list.back14.04
   mv ubuntu14.04.source /etc/apt/sources.list
fi
apt-get update
