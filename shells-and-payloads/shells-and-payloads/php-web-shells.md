# PHP Web Shells

***

Hypertext Preprocessor or [PHP](https://www.php.net) is an open-source general-purpose scripting language typically used as part of a web stack that powers a website. At the time of this writing (October 2021), PHP is the most popular `server-side programming language`. According to a [recent survey](https://w3techs.com/technologies/details/pl-php) conducted by W3Techs, "PHP is used by `78.6%` of all websites whose server-side programming language we know".

<mark style="color:green;">**PHP Login Page**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/rconfig.png)

Recall the rConfig server from earlier in this module? It uses PHP. We can see a `login.php` file. So when we select the login button after filling out the Username and Password field, that information is processed server-side using PHP. Knowing that a web server is using PHP gives us pentesters a clue that we may gain a PHP-based web shell on this system. Let's work through this concept hands-on.

***

### <mark style="color:red;">Hands-on With a PHP-Based Web Shell.</mark>

Go ahead and log in to rConfig with the default credentials (admin:admin), then navigate to `Devices` > `Vendors` and click `Add Vendor`.

**Vendors Tab**

![image](https://academy.hackthebox.com/storage/modules/115/vendors_tab.png)

We will be using [WhiteWinterWolf's PHP Web Shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell). We can download this or copy and paste the source code into a `.php` file. Keep in mind that the file type is significant, as we will soon witness. Our goal is to upload the PHP web shell via the Vendor Logo `browse` button. Attempting to do this initially will fail since rConfig is checking for the file type. It will only allow uploading image file types (.png,.jpg,.gif, etc.). However, we can bypass this utilizing `Burp Suite`.

Start Burp Suite, navigate to the browser's network settings menu and fill out the proxy settings. `127.0.0.1` will go in the IP address field, and `8080` will go in the port field to ensure all requests pass through Burp (recall that Burp acts as the web proxy).

**Proxy Settings**

![image](https://academy.hackthebox.com/storage/modules/115/proxy_settings.png)

Our goal is to change the `content-type` to bypass the file type restriction in uploading files to be "presented" as the vendor logo so we can navigate to that file and have our web shell.

***

### <mark style="color:red;">Bypassing the File Type Restriction</mark>

With Burp open and our web browser proxy settings properly configured, we can now upload the PHP web shell. Click the browse button, navigate to wherever our .php file is stored on our attack box, and select open and `Save` (we may need to accept the PortSwigger Certificate). It will seem as if the web page is hanging, but that's just because we need to tell Burp to forward the HTTP requests. Forward requests until you see the POST request containing our file upload. It will look like this:

**Post Request**

![Burp](https://academy.hackthebox.com/storage/modules/115/burp.png)

As mentioned in an earlier section, you will notice that some payloads have comments from the author that explain usage, provide kudos and links to personal blogs. This can give us away, so it's not always best to leave the comments in place. We will change Content-type from `application/x-php` to `image/gif`. This will essentially "trick" the server and allow us to upload the .php file, bypassing the file type restriction. Once we do this, we can select `Forward` twice, and the file will be submitted. We can turn the Burp interceptor off now and go back to the browser to see the results.

**Vendor Added**

![Burp](https://academy.hackthebox.com/storage/modules/115/added_vendor.png)

The message: 'Added new vendor NetVen to Database\` lets us know our file upload was successful. We can also see the NetVen vendor entry with the logo showcasing a ripped piece of paper. This means rConfig did not recognize the file type as an image, so it defaulted to that image. We can now attempt to use our web shell. Using the browser, navigate to this directory on the rConfig server:

`/images/vendor/connect.php`

This executes the payload and provides us with a non-interactive shell session entirely in the browser, allowing us to execute commands on the underlying OS.

**Webshell Success**

![image](https://academy.hackthebox.com/storage/modules/115/web_shell_now.png)

***

