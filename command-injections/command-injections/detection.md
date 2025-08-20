# Detection

***

The process of detecting basic OS Command Injection vulnerabilities is the same process for exploiting such vulnerabilities. We attempt to append our command through various injection methods. If the command output changes from the intended usual result, we have successfully exploited the vulnerability.&#x20;

***

### <mark style="color:red;">Command Injection Detection</mark>

When we visit the web application in the below exercise, we see a `Host Checker` utility that appears to ask us for an IP to check whether it is alive or not:

&#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_exercise_1.jpg" alt=""><figcaption></figcaption></figure>

We can try entering the localhost IP `127.0.0.1` to check the functionality, and as expected, it returns the output of the `ping` command telling us that the localhost is indeed alive:&#x20;

<figure><img src="https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_exercise_2.jpg" alt=""><figcaption></figcaption></figure>

Although we do not have access to the source code of the web application, we can confidently guess that the IP we entered is going into a `ping` command since the output we receive suggests that. As the result shows a single packet transmitted in the ping command, the command used may be as follows:

```bash
ping -c 1 OUR_INPUT
```

If our input is not sanitized and escaped before it is used with the `ping` command, we may be able to inject another arbitrary command. So, let us try to see if the web application is vulnerable to OS command injection.

***

### <mark style="color:red;">Command Injection Methods</mark>

To inject an additional command to the intended one, we may use any of the following operators:

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Injection Operator</strong></td><td><strong>Injection Character</strong></td><td><strong>URL-Encoded Character</strong></td><td><strong>Executed Command</strong></td></tr><tr><td>Semicolon</td><td><code>;</code></td><td><code>%3b</code></td><td>Both</td></tr><tr><td>New Line</td><td></td><td><code>%0a</code></td><td>Both</td></tr><tr><td>Background</td><td><code>&#x26;</code></td><td><code>%26</code></td><td>Both (second output generally shown first)</td></tr><tr><td>Pipe</td><td><code>|</code></td><td><code>%7c</code></td><td>Both (only second output is shown)</td></tr><tr><td>AND</td><td><code>&#x26;&#x26;</code></td><td><code>%26%26</code></td><td>Both (only if first succeeds)</td></tr><tr><td>OR</td><td><code>||</code></td><td><code>%7c%7c</code></td><td>Second (only if first fails)</td></tr><tr><td>Sub-Shell</td><td><code>``</code></td><td><code>%60%60</code></td><td>Both (Linux-only)</td></tr><tr><td>Sub-Shell</td><td><code>$()</code></td><td><code>%24%28%29</code></td><td>Both (Linux-only)</td></tr></tbody></table>

We can use any of these operators to inject another command so `both` or `either` of the commands get executed. **`We would write our expected input (e.g., an IP), then use any of the above operators, and then write our new command.`**

Tip: In addition to the above, there are a few unix-only operators, that would work on Linux and macOS, but would not work on Windows, such as wrapping our injected command with double backticks (` `` `) or with a sub-shell operator (`$()`).

In general, for basic command injection, all of these operators can be used for command injections `regardless of the web application language, framework, or back-end server`. So, if we are injecting in a `PHP` web application running on a `Linux` server, or a `.Net` web application running on a `Windows` back-end server, or a `NodeJS` web application running on a `macOS` back-end server, our injections should work regardless.

{% hint style="warning" %}
Note: The only exception may be the semi-colon `;`, which will not work if the command was being executed with `Windows Command Line (CMD)`, but would still work if it was being executed with `Windows PowerShell`.
{% endhint %}
