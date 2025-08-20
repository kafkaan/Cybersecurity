# Antak Webshell

***

### <mark style="color:red;">ASPX and a Quick Learning Tip</mark>

One great resource to use in learning is `IPPSEC's` blog site [ippsec.rocks](https://ippsec.rocks/?). The site is a powerful learning tool. Take, for example, the concept of web shells. We can use his site to type in the concept we want to learn, like aspx.

![IPPSEC Rocks](https://academy.hackthebox.com/storage/modules/115/ippsecrocks.png)

***

### <mark style="color:red;">ASPX Explained</mark>

`Active Server Page Extended` (`ASPX`) is a file type/extension written for [Microsoft's ASP.NET Framework](https://docs.microsoft.com/en-us/aspnet/overview). On a web server running the ASP.NET framework, web form pages can be generated for users to input data. On the server side, the information will be converted into HTML. We can take advantage of this by using an ASPX-based web shell to control the underlying Windows operating system. Let's witness this first-hand by utilizing the Antak Webshell.

***

### <mark style="color:red;">Antak Webshell</mark>

Antak is a web shell built-in ASP.Net included within the [Nishang project](https://github.com/samratashok/nishang). Nishang is an Offensive PowerShell toolset that can provide options for any portion of your pentest. Since we are focused on web applications for the moment, let's keep our eyes on `Antak`. Antak utilizes PowerShell to interact with the host, making it great for acquiring a web shell on a Windows server. The UI is even themed like PowerShell. It's time to dive in and experiment with Antak.

***

### <mark style="color:red;">Working with Antak</mark>

The Antak files can be found in the `/usr/share/nishang/Antak-WebShell` directory.

```shell-session
mrroboteLiot@htb[/htb]$ ls /usr/share/nishang/Antak-WebShell

antak.aspx  Readme.md
```

Antak web shell functions like a Powershell Console. However, it will execute each command as a new process. It can also execute scripts in memory and encode commands you send. As a web shell, Antak is a pretty powerful tool.

***

### <mark style="color:red;">Antak Demonstration</mark>

**Move a Copy for Modification**

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx
```
{% endcode %}

Make sure you set credentials for access to the web shell. Modify `line 14`, adding a user (green arrow) and password (orange arrow). This comes into play when you browse to your web shell, much like Laudanum. This can help make your operations more secure by ensuring random people can't just stumble into using the shell. It can be prudent to remove the ASCII art and comments from the file. These items in a payload are often signatured on and can alert the defenders/AV to what you are doing.

**Modify the Shell for Use**

![image](https://academy.hackthebox.com/storage/modules/115/antak-changes.png)

**Shell Success**

![image](https://academy.hackthebox.com/storage/modules/115/antak-creds-prompt.png)

As seen in the following image, we will be granted access if our credentials are entered properly.

![image](https://academy.hackthebox.com/storage/modules/115/antak-success.png)

**Issuing Commands**

![image](https://academy.hackthebox.com/storage/modules/115/antak-commands.png)
