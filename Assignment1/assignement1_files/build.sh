#! /bin/bash

apt-get update
apt-get install -y docker.io john
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall

usermod -aG docker syssec
systemctl enable docker

docker build -t syssec-exercise:2021 . &&\
docker run --restart always -i -d -p 8443:443 -p 8022:22 --name exploits syssec-exercise:2021
