# Client-Side Validation

***

### <mark style="color:red;">Client-Side Validation</mark>

The exercise at the end of this section shows a basic `Profile Image` functionality, frequently seen in web applications that utilize user profile features, like social media web applications:

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_profile_image_upload.jpg" alt=""><figcaption></figcaption></figure>

However, this time, when we get the file selection dialog, we cannot see our `PHP` scripts (or it may be greyed out), as the dialog appears to be limited to image formats only:

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_select_file_types.jpg" alt=""><figcaption></figcaption></figure>

We may still select the `All Files` option to select our `PHP` script anyway, but when we do so, we get an error message saying (`Only images are allowed!`), and the `Upload` button gets disabled:

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_select_denied.jpg" alt=""><figcaption></figcaption></figure>

This indicates some form of file type validation, so we cannot just upload a web shell through the upload form as we did in the previous section. Luckily, all validation appears to be happening on the front-end, as the page never refreshes or sends any HTTP requests after selecting our file. So, we should be able to have complete control over these client-side validations.

As mentioned earlier, to bypass these protections, we can either `modify the upload request to the back-end server`, or we can `manipulate the front-end code to disable these type validations`.

***

### <mark style="color:red;">Back-end Request Modification</mark>

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_normal_request.jpg" alt=""><figcaption></figcaption></figure>

If we capture the upload request with `Burp`, we see the following request being sent by the web application:

<figure><img src="../../.gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

The web application appears to be sending a standard HTTP upload request to `/upload.php`. This way, we can now modify this request to meet our needs without having the front-end type validation restrictions. If the back-end server does not validate the uploaded file type, then we should theoretically be able to send any file type/content, and it would be uploaded to the server.

The two important parts in the request are `filename="HTB.png"` and the file content at the end of the request. If we modify the `filename` to `shell.php` and modify the content to the web shell we used in the previous section; we would be uploading a `PHP` web shell instead of an image.

So, let's capture another image upload request, and then modify it accordingly:

<figure><img src="../../.gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

Note: We may also modify the `Content-Type` of the uploaded file, though this should not play an important role at this stage, so we'll keep it unmodified.

As we can see, our upload request went through, and we got `File successfully uploaded` in the response. So, we may now visit our uploaded file and interact with it and gain remote code execution.

***

### <mark style="color:red;">Disabling Front-end Validation</mark>

To start, we can click \[`CTRL+SHIFT+C`] to toggle the browser's `Page Inspector`, and then click on the profile image, which is where we trigger the file selector for the upload form:

<figure><img src="https://academy.hackthebox.com/storage/modules/136/file_uploads_element_inspector.jpg" alt=""><figcaption></figcaption></figure>

This will highlight the following HTML file input on line `18`:

{% code overflow="wrap" fullWidth="true" %}
```html
<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
```
{% endcode %}

Here, we see that the file input specifies (`.jpg,.jpeg,.png`) as the allowed file types within the file selection dialog. However, we can easily modify this and select `All Files` as we did before, so it is unnecessary to change this part of the page.

The more interesting part is `onchange="checkFile(this)"`, which appears to run a JavaScript code whenever we select a file, which appears to be doing the file type validation. To get the details of this function, we can go to the browser's `Console` by clicking \[`CTRL+SHIFT+K`], and then we can type the function's name (`checkFile`) to get its details:

```javascript
function checkFile(File) {
...SNIP...
    if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
        $('#error_message').text("Only images are allowed!");
        File.form.reset();
        $("#submit").attr("disabled", true);
    ...SNIP...
    }
}
```

The key thing we take from this function is where it checks whether the file extension is an image, and if it is not, it prints the error message we saw earlier (`Only images are allowed!`) and disables the `Upload` button. We can add `PHP` as one of the allowed extensions or modify the function to remove the extension check.

Luckily, we do not need to get into writing and modifying JavaScript code. We can remove this function from the HTML code since its primary use appears to be file type validation, and removing it should not break anything.

To do so, we can go back to our inspector, click on the profile image again, double-click on the function name (`checkFile`) on line `18`, and delete it:

<figure><img src="../../.gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>

Once we upload our web shell using either of the above methods and then refresh the page, we can use the `Page Inspector` once more with \[`CTRL+SHIFT+C`], click on the profile image, and we should see the URL of our uploaded web shell:

```html
<img src="/profile_images/shell.php" class="profile-image" id="profile-image">
```

If we can click on the above link, we will get to our uploaded web shell, which we can interact with to execute commands on the back-end server:

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_php_manual_shell.jpg)
