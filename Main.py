import discord
from discord.ext import commands
import subprocess
import datetime
import shodan
import subprocess
from selenium import webdriver
import whois
import base64
import requests
import re
import time

# Take discord API from TXT
with open("Api-key.txt", 'r') as file:
    for line in file:
        if "=" in line:
            idx= line.index("=")
            d_api = line[idx+1:].strip()
            break

def generate_analysis_shodan(dom):
    result = []
    emails = []
    indicator = False
    start = "Shodan"

    with open(f"{dom}.txt", 'r') as file:
        for line in file:
            if indicator:
                result.append(line.strip())

            if start in line:
                indicator = True
    
    for line in result:
        if line.strip() != "":
                emails.append(line)

    with open(f'fnl_res.txt', 'a') as f:
        f.write(f"\n")
        if result:
            f.write(f"Shodan Result: \n")
            for line in result:
                f.write(line+"\n")
        else:
            f.write(f"Shodan didnt found anything with {dom}\n")

def take_all_links_dm(dom):
    result = []
    result2 = []
    indicator = False
    start = "[*] Hosts found:"

    with open(f"hasil.txt", 'r') as file:
        for line in file:
            if indicator:
                result.append(line.strip())

            if start in line:
                indicator = True

    for line in result:
        if line.strip() != "":
            result2.append(line)

    with open(f'fnl_res.txt', 'a') as f:
        if result2:
            f.write(f"\nHOST That Has Been Founded:\n")
            for line in result2:
                f.write(line+"\n")
        else:
            f.write(f"No Host Found\n")

def take_all_links_ip(dom):
    result = []
    result2 = []
    indicator = False
    start = "[*] IPs found:"
    end = " "

    with open(f"hasil.txt", 'r') as file:
        for line in file:
            if indicator:
                if end in line:
                    break
                result.append(line.strip())

            if start in line:
                indicator = True

    for line in result:
        if line.strip() != "":
            result2.append(line)

    with open(f'fnl_res.txt', 'w') as f:
            f.write("")

    with open(f'fnl_res.txt', 'a') as f:
        if result2:
            f.write(f"IP That Has Been Founded:\n")
            for line in result2:
                f.write(line+"\n")
        else:
            f.write(f"No IP Found\n")

def generate_analysis_ns(dom):
    with open(f'ip.txt', 'r') as f:
        data = []
        for line in f:
            data = line.split("#")
        
    with open(f'fnl_res.txt', 'a') as f:
        f.write(f"\n")
        if data:
            f.write(f"Name Server OF {dom}:{data[0]} Located in {data[1]} {data[2]} Postal Code {data[3]} With Latitude {data[4]} and Longitude {data[5]}, ISP Company {data[6]}\n")
        else:
            f.write(f"NS Lookup did not found the data, please check the IP or DOMAIN\n")

def generate_analysis_vt(dom):
    result = []
    malicious = []
    indicator = False
    start = "VirusTotal"
    end = "WHOIS"

    with open(f"{dom}.txt", 'r') as file:
        for line in file:
            if indicator:
                if end in line:
                    break
                result.append(line.strip())

            if start in line:
                indicator = True

    for line in result:
        if "undetected" in line or "unrated" in line or "clean" in line:
            continue
        else:
            if line.strip() != "":
                malicious.append(line)

    with open(f'fnl_res.txt', 'a') as f:
        f.write(f"Analytic Of {dom}:\n")
        if malicious:
            f.write(f"WARNING: This IP or DOMAIN is Detected MALICIOUS on Virus Total Judgement!!!\n")
            for line in malicious:
                f.write(line+"\n")
        else:
            f.write(f"This IP or DOMAIN is detected NOT MALICIOUS on Virus Total judgement!!!\n")


def generate_analysis_email(dom):
    result = []
    emails = []
    indicator = False
    start = "Hunterio"

    with open(f"{dom}.txt", 'r') as file:
        for line in file:
            if indicator:
                if "Shodan" in line:
                    break

                result.append(line.strip())

            if start in line:
                indicator = True

    indicator = False
    start = "[*] Emails found:"
    end = "Hunterio"
    temp = 0
    with open(f"{dom}.txt", 'r') as file:
        for line in file:

            if indicator and temp ==0:
                if end in line:
                    break
                result.append(line.strip())

            if temp == 1:
                temp = 0

            if start in line:
                indicator = True
                temp = 1

    for line in result:
        if line.strip() != "":
                emails.append(line)
            

    with open(f'fnl_res.txt', 'a') as f:
        if emails:
            f.write(f"\nEmail Were Founded Related With This Domain:\n")
            for line in emails:
                f.write(line+"\n")
        else:
 
            f.write(f"\nNo Email Were Found That Are Related With This Domain \n")

    return emails


def add_logo(dom):
    
    with open("Logo.txt", 'r') as source:
        content = source.read()

    with open(f"fnl_res.txt", 'a') as target:
        target.write(content)

def generate_analysis_wh(dom):
    result = []
    result2 = []
    indicator = False
    start = "WHOIS"
    end = "TheHarvester"

    with open(f"{dom}.txt", 'r') as file:
        for line in file:
            if indicator:
                if end in line:
                    break
                result.append(line.strip())

            if start in line:
                indicator = True

    for line in result:
        if line.strip() != "":
            result2.append(line)

    with open(f'fnl_res.txt', 'a') as f:
        f.write(f"\n")
        if result2:
            for line in result2:
                f.write(line+"\n")
        else:
            f.write(f"This IP or DOMAIN is detected NOT MALICIOUS on Virus Total judgement!!!\n")

def generate_analysis_th(dom):
    result = []
    result2 = []
    indicator = False
    start = "[*] Interesting Urls"
    end = " "
    temp =0
    with open(f"{dom}.txt", 'r') as file:
        for line in file:
            if indicator and temp == 0:
                if end in line:
                    break
                result.append(line.strip())

            if temp == 1:
                temp = 0

            if start in line:
                indicator = True
                temp =1

    for line in result:
        if line.strip() != "":
            result2.append(line)

    with open(f'fnl_res.txt', 'a') as f:
        f.write(f"\n")
        if result2:
            f.write(f"Interesting URLs Was Founded!!! (to see full list we will send another TXT file)\n")
            for line in result2:
                f.write(line+"\n")
        else:
            f.write(f"Interesting Sub Domain Not Found. To see Full list we will send another TXT file\n")

def generate_analysis_th_lk(dom):
    result = []
    result2 = []
    indicator = False
    start = "[*] LinkedIn Links"
    end = " "
    temp =0
    with open(f"{dom}.txt", 'r') as file:
        for line in file:
            if indicator and temp == 0:
                if end in line:
                    break
                result.append(line.strip())

            if temp == 1:
                temp = 0

            if start in line:
                indicator = True
                temp =1

    for line in result:
        if line.strip() != "":
            result2.append(line)

    with open(f'fnl_res.txt', 'a') as f:
        f.write(f"\n")
        if result2:
            f.write(f"LinkedIn Profile were founded related to this domain!!! \n")
            for line in result2:
                f.write(line+"\n")
        else:
            f.write(f"No LinkedIn Profile were founded That Are Related With This Domain/IP\n")

def analyzer_txt(dom):
    add_logo(dom)
    generate_analysis_vt(dom)
    generate_analysis_email(dom)
    generate_analysis_wh(dom)
    generate_analysis_th(dom)
    generate_analysis_th_lk(dom)
    generate_analysis_ns(dom)
    take_all_links_ip(dom)
    take_all_links_dm(dom)
    
    

def check_ip_domain(dom):
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    if re.match(ip_pattern, dom):
        return "IP"

    else:
        return "DOMAIN"

def Ns_lookup(dom,api):
    if check_ip_domain(dom) == "DOMAIN":
        with open("ip.txt", 'w') as file:
            file.write("")
        command = f"dig +short A {dom} >> ip.txt"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        with open("ip.txt", 'r') as file:
            for line in file:
                ip = line
    else:
        ip = dom

    url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api}&ip={ip}"

    response = requests.get(url)

    data = response.json()

    location = data['ip'],data['city'], data['country_name'], data['zipcode'], data['latitude'], data['longitude'],data['isp']
    result = '#'.join([str(item) for item in location])
    with open("ip.txt", 'w') as file:
        file.write(result)


def hunter_io(dom,api):

    url = f'https://api.hunter.io/v2/domain-search?domain={dom}&api_key={api}'

    response = requests.get(url)

    if response.status_code == 200:

        out = ""
        data = response.json()
        emails = data['data']['emails']
        for email in emails:
            out+= email['value']+"\n"
        with open(f"{dom}.txt", "a") as file:
            file.write(out)
        return True
    else:
        with open(f"{dom}.txt", "a") as file:
            file.write(f"Error: {response.status_code} - {response.text}")
        return False

def sho_dan(query, api_key):

    C_api = shodan.Shodan(api_key)

    sho = C_api.search(query)

    if sho:
        with open(f"{query}.txt", "a") as file:
            for result in sho["matches"]:
                file.write(f"IP: {result['ip_str']}\n")
                file.write(f"Port: {result['port']}\n")
                file.write(f"Data: {result['data']}\n")
                file.write("\n")

def sher_lock(name):

    with open(f"{name}.txt", "w") as file:
        file.write("")
    command = f"sherlock {name} >> {name}.txt"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        print("theHarvester executed successfully!")
        return True
    else:
        print(f"theHarvester failed with error code {process.returncode}:")
        print(stderr.decode())
        return False

def harvest(web):

    with open("hasil.txt", "w") as file:
        file.write("")
    command = f"theHarvester -d {web} -b all >> hasil.txt"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        print("theHarvester executed successfully!")
        isi = []
        with open("hasil.txt", "r") as f:
            while True:
                for line in f:
                    if "[*] Interesting" in line:
                        isi.append(line)
                        for line in f:
                            if " " in line:
                                break
                            isi.append(line)
                            
                    if "[*] LinkedIn" in line:
                        isi.append(line)
                        for line in f:
                            if " " in line:
                                break
                            isi.append(line)
                        break

                    if "[*] Emails" in line:
                        isi.append(line)
                        for line in f:
                            if " " in line:
                                break
                            isi.append(line)
                break
            
        with open(f'{web}.txt', 'a') as file:
            for i in isi:
                file.write(i)
        return True
    else:
        print(f"theHarvester failed with error code {process.returncode}:")
        print(stderr.decode())
        return False

def Way_back(url,date,loop):
    web = f"https://web.archive.org/web/{date}000000/{url}"
    call = webdriver.Firefox()
    call.get(web)
    time.sleep(10)
    call.save_screenshot(f"{loop}-{url}.png")
    call.quit()

    return date

def extract_whois():
    with open("hasil2.txt", 'r') as file:
        content = file.read()

        start = "Registrars."
        end = "If you wish to contact this "

        idx_s = content.find(start)
        idx_e = content.find(end)

        if idx_s != -1 and idx_e != -1:

            extrac = content[idx_s + len(start):idx_e].strip()

            with open('hasil3.txt', 'w') as f:
                f.write(extrac)

            with open('hasil3.txt', 'r') as f:
                isi = f.readlines()

            isi_up = isi[:-5]

            with open('hasil3.txt', 'w') as f:
                f.writelines(isi_up)

            return True
        else:
            return False

def who_is(web):
    with open('hasil2.txt', 'w') as f:
        f.write("")
    command = f"whois {web} >> hasil2.txt"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        if extract_whois() == True:
            return True
        else:
            if who_is(web) == True:
                return True
            else:
                return False
    else:
        return stderr

def who_is(url):
    
    with open('hasil3.txt', 'w') as f:
        f.write("")
    search = whois.whois(url)

    out = f"WHOIS Result of {url}:\n"
    out += f"Domain Name: {search.domain_name}\n"
    out += f"Domain Status: {search.status}\n"
    out += f"Registrar: {search.registrar}\n"
    out += f"Creation Date: {search.creation_date}\n"
    out += f"Expiration Date: {search.expiration_date}\n"
    out += f"Registrar Name: {search.registrar}\n"
    out += f"Registrar Email: {search.registrar_email}\n"
    out += f"Registrar Phone: {search.registrar_phone}\n"
    out += f"Registrar Country: {search.registrar_country}\n"
    out += f"Registrar City: {search.registrar_city}\n"
    out += f"Registrant Name: {search.registrant_name}\n"
    out += f"Registrant Email: {search.registrant_email}\n"
    out += f"Registrant Phone: {search.registrat_phone}\n"
    out += f"Registrant Organization: {search.registrant_org}\n"
    out += f"Name Server: {search.name_servers}\n"

    with open('hasil3.txt', 'w') as f:
        f.write(out)

    return True


def clean_report_url(data, api):
    report = virus_total_URL(data, api)
    if report:
        result = []
        for scan in report['data']['attributes']['last_analysis_results']:
            temp = f"{scan} = {report['data']['attributes']['last_analysis_results'][scan]['result']}"
            result.append(temp)
        return result
    else:
        return "Failed to run this command, Please Try again in a few minutes!"

def virus_total_URL(data, api):

    url_id = base64.urlsafe_b64encode(data.encode()).decode().strip("=")

    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "accept": "application/json",
        "x-apikey": f"{api}"
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print("failed to run virus total")


bot = commands.Bot(command_prefix="!", intents=discord.Intents.all())
@bot.event
async def on_ready():
    print("The bot is now online!")
    

@bot.command(aliases=["OSINT"])
async def osint(ctx):
    List_api = []
    with open("Api-key.txt", 'r') as file:
        for line in file:
            if "=" in line:
                idx= line.index("=")
                api = line[idx+1:].strip()
                List_api.append(api)

    await ctx.send("Working...")
    
    message = ctx.message.content
    message = message.split()

    if len(message) == 1 or "-h" in message or "-help" in message:
        await ctx.send(f"Ini menu help!\n-h/-help     : display help menu\n-vt               : Run virus total with URL")
    
    elif "-p" in message and message.index("-p") != len(message)-1:

        await ctx.send("This Operation May Take Several Minutes!")
        uname = message[message.index("-p")+1]

        if sher_lock(uname) == True:
            await ctx.send("Username search done!")
            await ctx.send("Result: ", file=discord.File(f"{uname}.txt"))

        else:
            await ctx.send("Something went wrong in username search, moving to next sequence!")

        
    elif "-d" in message and message.index("-d") != len(message)-1:
        dom = message[message.index("-d")+1]
       

        with open(f"{dom}.txt", "w") as file:
            file.write(f"OSINT Of A Domain: {dom}")
            file.write("\n\n")
            file.write(f"###  VirusTotal RESULT  ###")
            file.write("\n\n")


        # VirusTotal Checking
        result = clean_report_url(dom, List_api[1])
        result = "\n".join(result)
        with open(f"{dom}.txt", "a") as file:
            file.write(f"{result}")

        with open(f"{dom}.txt", "a") as file:
            file.write(f"\n\n")
            file.write(f"###  WHOIS RESULT  ###")
            file.write(f"\n\n")


        # WHOis
        if who_is(dom) == True:
            with open(f"hasil3.txt", "r") as file:
                isi = file.read()
            with open(f"{dom}.txt", "a") as file:
                file.write(isi)
        else:
            await ctx.send(f"Whois Failed!!!")     

        with open(f"{dom}.txt", "a") as file:
            file.write(f"\n\n")
            file.write(f"###  TheHarvester RESULT  ###")
            file.write(f"\n\n")


        # TheHarvester
        if harvest(dom) == True:
            print(f"The harvester Success for {dom}")
        else:
            await ctx.send("The Harvester Failed To Run")


        with open(f"{dom}.txt", "a") as file:
                file.write(f"\n\n")
                file.write(f"###  Hunterio Emailfinder  ###")
                file.write(f"\n")


        # Hunterio
        temp = hunter_io(dom, List_api[2])
        if temp == True:
            print(f"hunterio Success for {dom}")
        else:
            await ctx.send("Hunterio Failed To Run")

        # Geoiplocation
        Ns_lookup(dom, List_api[3])


        # Shodan
        if "-sh" in message and message.index("-sh") != len(message)-1:
            
            api = message[message.index("-sh")+1]

            with open(f"{dom}.txt", "a") as file:
                file.write(f"\n\n")
                file.write(f"###  Shodan RESULT  ###")
                file.write(f"\n\n")

            sho_dan(dom,api)
            generate_analysis_shodan(dom)

        

        # Wayback Machine
        elif "-wb" in message and message.index("-wb") != len(message)-1:
            await ctx.send("This Operation May Take Several Minutes! (WayBack Machine)")

            time = message[message.index("-wb")+1]
            
            time_c = datetime.datetime.strptime(time, "%Y%m%d")
            today = datetime.datetime.today()

            ##### looping year #####
            loop = 0

            while time_c <= today:
                loop = loop + 1
                
                await ctx.send(f"WEB Preview {Way_back(dom,time,loop)}:", file=discord.File(f"{loop}-{dom}.png"))

                time2 = time[:4]
                year = int(time2)
                count = year + 1
                time = str(count) + time[4:]
                time_c = datetime.datetime.strptime(time, "%Y%m%d")
            
        await ctx.send("Analyzing!!!, please wait...")
        with open(f'fnl_res.txt', 'w') as f:
            f.write(f"")
        analyzer_txt(dom)



    elif "-s" in message and message.index("-s") != len(message)-1:
        dom = message[message.index("-s")+1]
        with open(f"{dom}.txt", "w") as file:
            file.write("")
        result2 = who_is(dom)
        with open(f"{dom}.txt", "a") as file:
            file.write(f"{result2}")

    await ctx.send("Result: ", file=discord.File(f"fnl_res.txt"))
    await ctx.send("Result: ", file=discord.File(f"all-links.txt"))
    await ctx.send("All Done!")


bot.run(f"{d_api}")