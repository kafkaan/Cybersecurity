# Laudanum, One Webshell to Rule Them All

***

Laudanum is a repository of ready-made files that can be used to inject onto a victim and receive back access via a reverse shell, run commands on the victim host right from the browser, and more. The repo includes injectable files for many different web application languages to include `asp, aspx, jsp, php,` and more. This is a staple to have on any pentest.&#x20;

***

### <mark style="color:red;">Laudanum Demonstration</mark>

<mark style="color:green;">**Move a Copy for Modification**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```
{% endcode %}

Add your IP address to the `allowedIps` variable on line `59`. Make any other changes you wish. It can be prudent to remove the ASCII art and comments from the file. These items in a payload are often signatured on and can alert the defenders/AV to what you are doing.

<mark style="color:green;">**Modify the Shell for Use**</mark>

<div data-full-width="true"><img src="https://academy.hackthebox.com/storage/modules/115/modify-shell.png" alt="image"></div>

We are taking advantage of the upload function at the bottom of the status page(`Green Arrow`) for this to work. Select your shell file and hit upload. If successful, it should print out the path to where the file was saved (Yellow Arrow). Use the upload function. Success prints out where the file went, navigate to it.

<mark style="color:green;">**Take Advantage of the Upload Function**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/laud-upload.png)

<mark style="color:green;">**Navigate to Our Shell**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/laud-nav.png)

We can now utilize the L10.129.42.197audanum shell we uploaded to issue commands to the host. We can see in the example that the `systeminfo` command was run.

**Shell Success**

![image](https://academy.hackthebox.com/storage/modules/115/laud-success.png)
