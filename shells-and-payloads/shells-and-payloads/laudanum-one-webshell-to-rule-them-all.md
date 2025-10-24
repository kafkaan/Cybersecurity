# Laudanum, One Webshell to Rule Them All

***

### <mark style="color:red;">Laudanum Demonstration</mark>

<mark style="color:green;">**Move a Copy for Modification**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```
{% endcode %}

<mark style="color:green;">**Modify the Shell for Use**</mark>

<div data-full-width="true"><img src="https://academy.hackthebox.com/storage/modules/115/modify-shell.png" alt="image"></div>

We are taking advantage of the upload function at the bottom of the status page(`Green Arrow`) for this to work. Select your shell file and hit upload. If successful, it should print out the path to where the file was saved (Yellow Arrow). Use the upload function. Success prints out where the file went, navigate to it.

<mark style="color:green;">**Take Advantage of the Upload Function**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/laud-upload.png)

<mark style="color:green;">**Navigate to Our Shell**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/laud-nav.png)

We can now utilize the L10.129.42.197audanum shell we uploaded to issue commands to the host. We can see in the example that the `systeminfo` command was run.

<mark style="color:green;">**Shell Success**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/laud-success.png)
