# Discord_OSINT

https://github.com/iqldnr/Discord_OSINT.git


        _____                           __  __     ___ 
  |/  \(_  |    /\   |\ | _  _ _  _ |  /  \(_ ||\ | |  
__)\__/__) |   /--\  | \|(_)| |||(_||  \__/__)|| \| |  


This is a Discord Bot That Runs OSINT!

Requirements to run this BOT:
1. you have to create+login account discord and take discord API at discord develop (https://discord.com/build/app-developers)
2. you have to create+login virustotal to get API account at (www.virustotal.com)
3. you have to create+login account hunterio to get API at (www.hunter.io)
4. you have to create+login account at ipgeolocation to get their API (https://ipgeolocation.io/)

Optional
1. Shodan API: you need to have Paid API, the free API cant really help...


This Program has been tested in Kali Linux, please use kali linux to prevent further errors.


How To Run:
1. git clone https://github.com/iqldnr/Discord_OSINT.git
2. cd DCOSINT
3. bash config.sh
4. Fill the Required API in Api-key.txt
5. Python Main.py

Invite the BOT to a server to run the BOT.


Option to run the program (In Discord):
1. !osint -p <username> 
2. !osint -d <domain/ip>
3. !osint -d <domain/ip> -sh <shodan_API>
4. !osint -d <domain/ip> -wb <yyyymmdd>
5. !osint -d <domain/ip> -sh <shodan_API> -wb <yyyymmdd>


-p means people to find a username registered in which site, im using Sherlock to run this command.

-d means domain to do a lookup and find information about the domain or IP, but better with the domain. with -d program will do scanning virus total, whois, the harvester, hunterio, and geolocation.

-sh meaning shodan it is optional on the -d parameter because it need paid shodan API to get the information

-wb means wayback machine, this thing will do a screenshot on the web archive result. we need to input past dates, this thing will do looping until the current date with an interval of 1 year.







Note: anything you see here is only for educational purposes!!
More note!: I still learning about asynchronous programming, maybe in the future will be implemented in this code, and also more features!!
