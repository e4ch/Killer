# KILLER TOOL (EDR Evasion)
It's an AV/EDR Evasion tool created to bypass security tools for learning, until now the tool is FUD.

# Features:

* Module Stomping for Memory scanning evasion
* DLL Unhooking by fresh ntdll copy
* IAT Hiding and Obfuscation & API Unhooking
* ETW Patching for bypassing some security controls
* Included sandbox evasion techniques & Basic Anti-Debugging
* Fully obfuscated (Functions - Keys - Shellcode) by XOR-ing
* Shellcode reversed and encrypted
* Moving payload into hallowed memory without using APIs 
* GetProcAddress & GetModuleHandle Implementation by @cocomelonc
* Runs without creating new thread & supports x64 and x86 architecture

# Update December 2024
MS Defender will detect ETW patching and is not using userland hooking. Some AV will detect this tool even with new keys, so some more changes could be needed. Check VT, as in the meantime surely many people have uploaded it there.

# How to use it

Generate your shellcode with msfvenom tool:

      msfvenom -p windows/x64/exec CMD=calc.exe -f py
      
Then copy the output into the new Python script and run it to generate the obfuscated code lines that need to get updated.
 
You can read more about the techniques in my articles:

* Part 1 => https://medium.com/@0xHossam/av-edr-evasion-malware-development-933e50f47af5
* Part 2 => https://medium.com/@0xHossam/av-edr-evasion-malware-development-p2-7a947f7db354
* Part 3 => https://medium.com/@0xHossam/unhooking-memory-object-hiding-3229b75618f7
* Part 4 => https://medium.com/@0xHossam/av-edr-evasion-malware-development-p-4-162662bb630e

This is the result when running:

![image](https://user-images.githubusercontent.com/82971998/230731975-a70abd1c-279b-4e79-9e91-6b5212b7db9a.png)

# PoC (Proof-of-Concept):

https://antiscan.me/images/result/07OkIKKhpRsG.png

![image](https://user-images.githubusercontent.com/82971998/230732045-ca2638fe-4f3c-4926-8f94-4fff817ca585.png)

# Important Notes

* First thanks to [Abdallah Mohammed](https://github.com/abdallah-elsharif) for helping me to develop it ^_^
* The tool is for educational purposes only
* Compile the code with Visual Studio compiler
* If you're not using the compile.bat file, but instead a Visual Studio project, then there are some changes to the default configuration needed:
  * Project Property Pages, Debugging: set Command to "killer.exe" and Working Directory to "$(TargetDir)" otherwise the tool will detect a name mismatch and quit when debugging with Visual Studio
  * For the C/C++, Preprocessor, Preprocessor Definitions: besides NDEBUG and _CONSOLE, add: _CRT_SECURE_NO_WARNINGS
