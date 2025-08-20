# Injecting Commands

### <mark style="color:red;">Injecting Our Command</mark>

We can add a semi-colon after our input IP `127.0.0.1`, and then append our command (e.g. `whoami`), such that the final payload we will use is (`127.0.0.1; whoami`), and the final command to be executed would be:

```bash
ping -c 1 127.0.0.1; whoami
```

First, let's try running the above command on our Linux VM to ensure it does run:

```shell-session
21y4d@htb[/htb]$ ping -c 1 127.0.0.1; whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.03 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.034/1.034/1.034/0.000 ms
21y4d
```

As we can see, the final command successfully runs, and we get the output of both commands (as mentioned in the previous table for `;`). Now, we can try using our previous payload in the `Host Checker` web application:

&#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_injection.jpg" alt=""><figcaption></figcaption></figure>

As we can see, the web application refused our input, as it seems only to accept input in an IP format. However, from the look of the error message, it appears to be originating from the front-end rather than the back-end. We can double-check this with the `Firefox Developer Tools` by clicking `[CTRL + SHIFT + E]` to show the Network tab and then clicking on the `Check` button again:

![Basic Injection](https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_injection_network.jpg)

As we can see, no new network requests were made when we clicked on the `Check` button, yet we got an error message. This indicates that the `user input validation is happening on the front-end`.

This appears to be an attempt at preventing us from sending malicious payloads by only allowing user input in an IP format. `However, it is very common for developers only to perform input validation on the front-end while not validating or sanitizing the input on the back-end.` This occurs for various reasons, like having two different teams working on the front-end/back-end or trusting front-end validation to prevent malicious payloads.

***

### <mark style="color:red;">Bypassing Front-End Validation</mark>

<mark style="color:green;">**Burp POST Request**</mark>

![Basic Injection](https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_repeater_1.jpg)

We can now customize our HTTP request and send it to see how the web application handles it. We will start by using the same previous payload (`127.0.0.1; whoami`). We should also URL-encode our payload to ensure it gets sent as we intend. We can do so by selecting the payload and then clicking `[CTRL + U]`. Finally, we can click `Send` to send our HTTP request:

<mark style="color:green;">**Burp POST Request**</mark>

![Basic Injection](https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_repeater_2.jpg)

As we can see, the response we got this time contains the output of the `ping` command and the result of the `whoami` command, `meaning that we successfully injected our new command`.

***

## <mark style="color:red;">Other Injection Operators</mark>

***

### <mark style="color:blue;">AND Operator</mark>

```bash
ping -c 1 127.0.0.1 && whoami
```

As we always should, let's try to run the command on our Linux VM first to ensure that it is a working command:

```shell-session
21y4d@htb[/htb]$ ping -c 1 127.0.0.1 && whoami
```

As we can see, the command does run, and we get the same output we got previously. Try to refer to the injection operators table from the previous section and see how the `&&` operator is different (if we do not write an IP and start directly with `&&`, would the command still work?).

Now, we can do the same thing we did before by copying our payload, pasting it in our HTTP request in `Burp Suite`, URL-encoding it, and then finally sending it:



<figure><img src="../../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

As we can see, we successfully injected our command and received the expected output of both commands.

***

### <mark style="color:blue;">OR Operator</mark>

Finally, let us try the `OR` (`||`) injection operator. The `OR` operator only executes the second command if the first command fails to execute. This may be useful for us in cases where our injection would break the original command without having a solid way of having both commands work. So, using the `OR` operator would make our new command execute if the first one fails.

If we try to use our usual payload with the `||` operator (`127.0.0.1 || whoami`), we will see that only the first command would execute:

```shell-session
21y4d@htb[/htb]$ ping -c 1 127.0.0.1 || whoami
```

This is because of how `bash` commands work. As the first command returns exit code `0` indicating successful execution, the `bash` command stops and does not try the other command. It would only attempt to execute the other command if the first command failed and returned an exit code `1`.

`Try using the above payload in the HTTP request, and see how the web application handles it.`

Let us try to intentionally break the first command by not supplying an IP and directly using the `||` operator (`|| whoami`), such that the `ping` command would fail and our injected command gets executed:

```shell-session
21y4d@htb[/htb]$ ping -c 1 || whoami
```

As we can see, this time, the `whoami` command did execute after the `ping` command failed and gave us an error message. So, let us now try the (`|| whoami`) payload in our HTTP request:&#x20;

<figure><img src="../../.gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

We see that this time we only got the output of the second command as expected. With this, we are using a much simpler payload and getting a much cleaner result.

Such operators can be used for various injection types, like SQL injections, LDAP injections, XSS, SSRF, XML, etc. We have created a list of the most common operators that can be used for injections:

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Injection Type</strong></td><td><strong>Operators</strong></td></tr><tr><td>SQL Injection</td><td><code>'</code> <code>,</code> <code>;</code> <code>--</code> <code>/* */</code></td></tr><tr><td>Command Injection</td><td><code>;</code> <code>&#x26;&#x26;</code></td></tr><tr><td>LDAP Injection</td><td><code>*</code> <code>(</code> <code>)</code> <code>&#x26;</code> <code>|</code></td></tr><tr><td>XPath Injection</td><td><code>'</code> <code>or</code> <code>and</code> <code>not</code> <code>substring</code> <code>concat</code> <code>count</code></td></tr><tr><td>OS Command Injection</td><td><code>;</code> <code>&#x26;</code> <code>|</code></td></tr><tr><td>Code Injection</td><td><code>'</code> <code>;</code> <code>--</code> <code>/* */</code> <code>$()</code> <code>${}</code> <code>#{}</code> <code>%{}</code> <code>^</code></td></tr><tr><td>Directory Traversal/File Path Traversal</td><td><code>../</code> <code>..\\</code> <code>%00</code></td></tr><tr><td>Object Injection</td><td><code>;</code> <code>&#x26;</code> <code>|</code></td></tr><tr><td>XQuery Injection</td><td><code>'</code> <code>;</code> <code>--</code> <code>/* */</code></td></tr><tr><td>Shellcode Injection</td><td><code>\x</code> <code>\u</code> <code>%u</code> <code>%n</code></td></tr><tr><td>Header Injection</td><td> <code>\r</code>  <code>%0d</code> <code>%0a</code> <code>%09</code></td></tr></tbody></table>
