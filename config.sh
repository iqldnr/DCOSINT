#!/bin/bash

#Update all packages
sudo apt update -y

#instal python and pip
sudo apt install python3 python3-pip -y

#pip install package
sudo pip3 install discord shodan selenium python-whois requests

#Install theHarvester
sudo apt install theharvester -y

#Install whois
sudo apt install whois -y

#Install Sherlock
sudo apt install sherlock -y

#Check if all packages and tools were installed successfully
if [ $? -eq 0 ]; then
  echo "All packages and tools installed successfully."
else
  echo "There was an error during the installation process."
fi
