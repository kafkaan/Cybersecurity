# SKILLS ASSESSEMENT

## <mark style="color:red;">Skills Assessment: Web Reconnaissance and Enumeration</mark>

> To complete this skills assessment, you'll apply various techniques such as using WHOIS, analyzing robots.txt, performing subdomain bruteforcing, and crawling websites. Follow the step-by-step instructions to demonstrate your proficiency in these areas.

## <mark style="color:red;">**Questions and Answers**</mark>

1. <mark style="color:green;">**What is the IANA ID of the registrar of the inlanefreight.com domain?**</mark>

Answer: 468

**Using WHOIS**

To find the IANA ID of the registrar for a domain, use the whois command:

```typescript
whois inlanefreight.com
```

Look for the Registrar IANA ID in the output. For example

```yaml
Registrar IANA ID: 468
```

![None](https://miro.medium.com/v2/resize:fit:700/1*NsaC2mn1jZH-xAhu7otGgA.png)

<mark style="color:green;">**2. What HTTP server software is powering the inlanefreight.htb site on the target system?**</mark>

Answer: nginx

```css
curl -i http://{IP_ADDRESS}:{PORT}
```

![None](https://miro.medium.com/v2/resize:fit:700/1*MLJ0r0XlDOXu1fHYxmdsnQ.png)

<mark style="color:green;">**3. What is the API key in the hidden admin directory that you have discovered on the target system?**</mark>

Answer: e963d863ee0e82ba7080fbf558ca0d3f

```bash
sudo nano /etc/hosts
<IP_ADDRESS>   inlanefreight.htb
<IP_ADDRESS>   web1137.inlanefreight.htb
<IP_ADDRESS>   dev.web1137.inlanefreight.htb
```

![None](https://miro.medium.com/v2/resize:fit:700/1*EAqQEZNxyI6-Rq8dSUL8pg.png)

<mark style="color:green;">**4. After crawling the inlanefreight.htb domain on the target system, what is the email address you have found?**</mark>

Answer: 1337testing@inlanefreight.htb

{% code fullWidth="true" %}
```css
gobuster vhost http://web1337.inlanefreight.htb:{PORT} -w /<path_to_wordlist> --append-domain -t 50 
```
{% endcode %}

![None](https://miro.medium.com/v2/resize:fit:700/1*CUFfNT9rV3uIHRTbjy2qjw.png)![None](https://miro.medium.com/v2/resize:fit:700/1*svezAu1eOL0qYiPJOgGt9w.png)

```bash
python3 ReconSpider.py http://dev.web1337.inlanefreight.htb{PORT}
cat results.json
```

![None](https://miro.medium.com/v2/resize:fit:700/1*Prl3Nfo2zkjxoPmW6eCjaA.png)

<mark style="color:green;">**5. What is the API key the inlanefreight.htb developers will be changing to?**</mark>

Answer: ba988b835be4aa97d068941dc852ff33

![None](https://miro.medium.com/v2/resize:fit:700/1*XtOP-y3V1qD6Jshb95qrHQ.png)
