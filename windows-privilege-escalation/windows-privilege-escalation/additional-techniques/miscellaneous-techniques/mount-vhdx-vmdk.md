# Mount VHDX/VMDK

### <mark style="color:red;">Mount VHDX/VMDK</mark>

{% hint style="warning" %}
Lors de l’**énumération**, on peut trouver des fichiers intéressants localement ou sur des partages réseau : mots de passe, clés SSH, etc.

* L’outil **Snaffler** permet de rechercher automatiquement des fichiers sensibles comme ceux contenant “pass”, des bases KeePass, clés SSH, web.config, etc.
* Les fichiers **.vhd, .vhdx, .vmdk** (disques virtuels Hyper-V et VMware) sont particulièrement intéressants.
* Sur un serveur web, des partages de sauvegarde peuvent contenir ces fichiers correspondant à des machines du réseau.
* Si un fichier contient une session d’un **admin de domaine**, on peut exploiter cela pour récupérer des **hashes NTLM ou tickets Kerberos**.
* Ces fichiers peuvent être **montés localement** sur Linux ou Windows pour explorer le système de fichiers comme si on y était connecté.
{% endhint %}

<mark style="color:green;">**Mount VMDK on Linux**</mark>

```shell-session
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk
```

<mark style="color:green;">**Mount VHD/VHDX on Linux**</mark>

```shell-session
guestmount --add WEBSRV10.vhdx  --ro /mnt/vhdx/ -m /dev/sda1
```

In Windows, we can right-click on the file and choose `Mount`, or use the `Disk Management` utility to mount a `.vhd` or `.vhdx` file. If preferred, we can use the [Mount-VHD](https://docs.microsoft.com/en-us/powershell/module/hyper-v/mount-vhd?view=windowsserver2019-ps) PowerShell cmdlet. Regardless of the method, once we do this, the virtual hard disk will appear as a lettered drive that we can then browse.

<figure><img src="../../../../.gitbook/assets/image (13) (1).png" alt=""><figcaption></figcaption></figure>

For a `.vmdk` file, we can right-click and choose `Map Virtual Disk` from the menu. Next, we will be prompted to select a drive letter. If all goes to plan, we can browse the target operating system's files and directories. If this fails, we can use VMWare Workstation `File --> Map Virtual Disks` to map the disk onto our base system. We could also add the `.vmdk` file onto our attack VM as an additional virtual hard drive, then access it as a lettered drive. We can even use `7-Zip` to extract data from a .`vmdk` file. This [guide](https://www.nakivo.com/blog/extract-content-vmdk-files-step-step-guide/) illustrates many methods for gaining access to the files on a `.vmdk` file.

<mark style="color:green;">**Retrieving Hashes using Secretsdump.py**</mark>

```shell-session
ecretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```
