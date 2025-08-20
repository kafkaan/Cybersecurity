# Burp Intruder

***

### <mark style="color:blue;">Target</mark>

As usual, we'll start up Burp and its pre-configured browser and then visit the web application from the exercise at the end of this section. Once we do, we can go to the Proxy History, locate our request, then right-click on the request and select `Send to Intruder`, or use the shortcut \[`CTRL+I`] to send it to `Intruder`.

We can then go to `Intruder` by clicking on its tab or with the shortcut \[`CTRL+SHIFT+I`], which takes us right to `Burp Intruder`:

![intruder\_target](https://academy.hackthebox.com/storage/modules/110/burp_intruder_target.jpg)

On the first tab, '`Target`', we see the details of the target we will be fuzzing, which is fed from the request we sent to `Intruder`.

***

### <mark style="color:blue;">Positions</mark>

The second tab, '`Positions`', is where we place the payload position pointer, which is the point where words from our wordlist will be placed and iterated over. We will be demonstrating how to fuzz web directories, which is similar to what's done by tools like `ffuf` or `gobuster`.

To check whether a web directory exists, our fuzzing should be in '`GET /DIRECTORY/`', such that existing pages would return `200 OK`, otherwise we'd get `404 NOT FOUND`. So, we will need to select `DIRECTORY` as the payload position, by either wrapping it with `§` or by selecting the word `DIRECTORY` and clicking on the `Add §` button:

![intruder\_position](https://academy.hackthebox.com/storage/modules/110/burp_intruder_position.jpg)

To read more about attack types, or check out this [link](https://portswigger.net/burp/documentation/desktop/tools/intruder/positions#attack-type).

Note: Be sure to leave the extra two lines at the end of the request, otherwise we may get an error response from the server.

***

### <mark style="color:blue;">Payloads</mark>

On the third tab, '`Payloads`', we get to choose and customize our payloads/wordlists. This payload/wordlist is what would be iterated over, and each element/line of it would be placed and tested one by one in the Payload Position we chose earlier. There are four main things we need to configure:

* Payload Sets
* Payload Options
* Payload Processing
* Payload Encoding

<mark style="color:green;">**Payload Sets**</mark>

The first thing we must configure is the `Payload Set`. The payload set identifies the Payload number, depending on the attack type and number of Payloads we used in the Payload Position Pointers:

![Payload Sets](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_set.jpg)

In this case, we only have one Payload Set, as we chose the '`Sniper`' Attack type with only one payload position. If we have chosen the '`Cluster Bomb`' attack type, for example, and added several payload positions, we would get more payload sets to choose from and choose different options for each. In our case, we'll select `1` for the payload set.

Next, we need to select the `Payload Type`, which is the type of payloads/wordlists we will be using. Burp provides a variety of Payload Types, each of which acts in a certain way. For example:

* `Simple List`: The basic and most fundamental type. We provide a wordlist, and Intruder iterates over each line in it.
* `Runtime file`: Similar to `Simple List`, but loads line-by-line as the scan runs to avoid excessive memory usage by Burp.
* `Character Substitution`: Lets us specify a list of characters and their replacements, and Burp Intruder tries all potential permutations.

<mark style="color:green;">**Payload Options**</mark>

Next, we must specify the Payload Options, which is different for each Payload Type we select in `Payload Sets`. For a `Simple List`, we have to create or load a wordlist. To do so, we can input each item manually by clicking `Add`, which would build our wordlist on the fly. The other more common option is to click on `Load`, and then select a file to load into Burp Intruder.

We will select `/opt/useful/seclists/Discovery/Web-Content/common.txt` as our wordlist. We can see that Burp Intruder loads all lines of our wordlist into the Payload Options table:

![Payload Options](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_wordlist.jpg)

We can add another wordlist or manually add a few items, and they would be appended to the same list of items. We can use this to combine multiple wordlists or create customized wordlists. In Burp Pro, we also can select from a list of existing wordlists contained within Burp by choosing from the `Add from list` menu option.

Tip: In case you wanted to use a very large wordlist, it's best to use `Runtime file` as the Payload Type instead of `Simple List`, so that Burp Intruder won't have to load the entire wordlist in advance, which may throttle memory usage.

<mark style="color:green;">**Payload Processing**</mark>

Another option we can apply is `Payload Processing`, which allows us to determine fuzzing rules over the loaded wordlist. For example, if we wanted to add an extension after our payload item, or if we wanted to filter the wordlist based on specific criteria, we can do so with payload processing.

Let's try adding a rule that skips any lines that start with a `.` (as shown in the wordlist screenshot earlier). We can do that by clicking on the `Add` button and then selecting `Skip if matches regex`, which allows us to provide a regex pattern for items we want to skip. Then, we can provide a regex pattern that matches lines starting with `.`, which is: `^\..*$`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_processing_1.jpg)

We can see that our rule gets added and enabled:

&#x20;![payload processing](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_processing_2.jpg)

<mark style="color:green;">**Payload Encoding**</mark>

The fourth and final option we can apply is `Payload Encoding`, enabling us to enable or disable Payload URL-encoding.

![payload encoding](https://academy.hackthebox.com/storage/modules/110/burp_intruder_payload_encoding.jpg)

We'll leave it enabled.

***

### <mark style="color:green;">Options</mark>

Finally, we can customize our attack options from the `Options` tab. There are many options we can customize (or leave at default) for our attack. For example, we can set the number of `retried on failure` and `pause before retry` to 0.

Another useful option is the `Grep - Match`, which enables us to flag specific requests depending on their responses. As we are fuzzing web directories, we are only interested in responses with HTTP code `200 OK`. So, we'll first enable it and then click `Clear` to clear the current list. After that, we can type `200 OK` to match any requests with this string and click `Add` to add the new rule. Finally, we'll also disable `Exclude HTTP Headers`, as what we are looking for is in the HTTP header:

![options match](https://academy.hackthebox.com/storage/modules/110/burp_intruder_options_match.jpg)

We may also utilize the `Grep - Extract` option, which is useful if the HTTP responses are lengthy, and we're only interested in a certain part of the response. So, this helps us in only showing a specific part of the response. We are only looking for responses with HTTP Code `200 OK`, regardless of their content, so we will not opt for this option.

Try other `Intruder` options, and use Burp help by clicking on `?` next to each one to learn more about each option.

Note: We may also use the `Resource Pool` tab to specify how much network resources Intruder will use, which may be useful for very large attacks. For our example, we'll leave it at its default values.

***

### <mark style="color:blue;">Attack</mark>

Now that everything is properly set up, we can click on the `Start Attack` button and wait for our attack to finish. Once again, in the free `Community Version`, these attacks would be very slow and take a considerable amount of time for longer wordlists.

The first thing we will notice is that all lines starting with `.` were skipped, and we directly started with the lines after them:

![intruder\_attack\_exclude](https://academy.hackthebox.com/storage/modules/110/burp_intruder_attack_exclude.jpg)

We can also see the `200 OK` column, which shows requests that match the `200 OK` grep value we specified in the Options tab. We can click on it to sort by it, such that we'll have matching results at the top. Otherwise, we can sort by `status` or by `Length`. Once our scan is done, we see that we get one hit `/admin`:

![intruder\_attack](https://academy.hackthebox.com/storage/modules/110/burp_intruder_attack.jpg)
