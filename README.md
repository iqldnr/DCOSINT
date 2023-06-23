# Discord_OSINT

https://github.com/iqldnr/Discord_OSINT.git


        _____                           __  __     ___ 
  |/  \(_  |    /\   |\ | _  _ _  _ |  /  \(_ ||\ | |  
__)\__/__) |   /--\  | \|(_)| |||(_||  \__/__)|| \| |  


This is a Discord Bot That Run OSINT!

Requirements to run this BOT:
1. you have to create+login account discord and take discord API at discord develop (https://discord.com/build/app-developers)
2. you have to create+login virustotal to get API account at (www.virustotal.com)
3. you have to create+login account hunterio to get API at (www.hunter.io)
4. you have to create+login account at ipgeolocation to get their API (https://ipgeolocation.io/)

Optional
1. Shodan API: you need to have Paid API, the free api cant really help...


This Program has been tested in Kali Linux, please use kali linux to prevent further error.


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


-p meaning people to find a username registered in wich site, im using sherlock to run this command.

-d meaning domain to do lookup and finding information about the domain or IP, but better with domain. with -d program will do scanning virustotal, whois, theharvester, hunterio, and geolocation.

-sh meaning shodan it is optional on -d parameter because of it need paid shodan api to get the information

-wb meaning wayback machine, this thing will do screenshot on web archive result. we need to input past date, this thing will do looping until curent date with interval 1 year.







Note: anything you see in here only for educational purposes!!
