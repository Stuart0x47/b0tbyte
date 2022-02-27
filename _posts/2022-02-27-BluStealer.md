---
title: BluStealer
date: 2022-02-27
categories: [malware, stealer]
tags: [blustealer]     # TAG names should always be lowercase
toc: true
comments: false

---

# BluStealer
- creator: unknown
- type: stealer, keylogger
- references:
    - https://www.gosecure.net/blog/2021/09/22/gosecure-titan-labs-technical-report-blustealer-malware-threat/
    - https://decoded.avast.io/anhho/blustealer/


## Components
1. ChromeRecovery.exe
    - gathers system information, such as the computer name, username, Windows version, antivirus solution, CPU name, GPU name, the amount of RAM, internal IP, and external IP
    - writes to C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Templates\credentials.txt
2. ConsoleApp8.exe (found in ChromeRecovery.exe)
    - saved, executed, and deleted from the Templates directory
    - steals credentials from Windows Vault and WinSCP and appends them to credentials.txt
3. ThunderFox.exe
    - targets Mozilla products: ThunderBird, FireFox, Waterfox, K-Meleon, IceDragon, Cyberfox, BlackHawK, Pale Moon
    - extracts login credentials from logins.json, key4.db, signons.sqlite, and key3.db. logins.json stores encrypted passwords for Mozilla products (legacy versions)
    - dumps to credentials.txt
4. Keylogging
    - polls user32.getAsyncKeyState, which determines whether a key is pressed or not at the time of the call
5. Crypto wallet stealing
    - Searches for crypto directories: Zcash, Armory, Bytecoin, Jaxx Liberty, Exodus, Ethereum, Electrum, Guarda, and Coinomi

## Exfil / C2
1. telegram and discord
    - https[:]//api.telegram.org/bot[BOT TOKEN]/sendMessage?chat_id=[MY_CHANNEL_ID]&text=[MY_MESSAGE_TEXT]
    - https[:]//api.telegram.org/bot[BOT TOKEN]/sendDocument?chat_id=[MY_CHANNEL_ID]&caption=[MY_CAPTION]
2. SMTP
    - written in MimeOLE format
    - contains credentials.txt and other stolen information


## SIEM
"AppData\Roaming\Microsoft\Windows\Templates\credentials.txt"

## IDS
```alert smtp $HOME_NET any -> $EXTERNAL_NET any (msg:"BluStealer SMTP Exfiltration"; flow:established, to_server; content:"Subject|3a 20|Passwords|3a 3a 3a 3a|"; nocase; fast_pattern; content:"X-MimeOLE|3a 20|"; tag:session,5,packets; reference:url, decoded.avast.io/anhho/blustealer/; classtype:trojan-activity; sid:900442; rev:1; metadata: created_at 2021-09-28, updated_at 2021-09-28, mitre_tactic_id TA0010, mitre_tactic_name Exfiltration, mitre_technique_id T1567, mitre_technique_name Exfiltration_Over_Web_Service;)```

```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Telegram GET SendMessage Activity"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/bot"; depth:4; content:"/sendMessage?chat_id="; distance:0; http.host; content:"api.telegram.org"; tag:session,5,packets; classtype:command-and-control; sid:900436; rev:1; metadata: created_at 2021-09-24, updated_at 2021-09-24;)```

```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Telegram POST SendMessage Activity"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/bot"; startswith; content:"/sendMessage"; distance:0; http.host; content:"api.telegram.org"; http.request_body; content:"chat_id="; tag:session,5,packets; classtype:command-and-control; sid:900437; rev:1; metadata: created_at 2021-09-24, updated_at 2021-09-24;)```

```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Telegram SendDocument Activity"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/bot"; content:"/sendDocument?chat_id="; distance:0; http.host; content:"api.telegram.org"; classtype:command-and-control; tag:session,5,packets; sid:900438; rev:1; metadata: created_at 2021-09-24, updated_at 2021-09-24;)```

```alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"[ConnectWise CRU] Telegram getMe Activity"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/bot"; depth:4; content:"/getMe"; isdataat:!2,relative; pcre:"/^\/bot\d+\:[A-Za-z0-9\-]+\/getMe\??$/"; http.host; content:"api.telegram.org"; tag:session,5,packets; classtype:command-and-control; sid:900439; rev:1; metadata: created_at 2021-09-24, updated_at 2021-09-24;)```
