
## ROP
- fill the stack with return addresses -> execute existing code
- syscall -> execve [Syscalls](https://x64.syscall.sh/) 
- return to libc
- stack pivoting
- https://docs.pwntools.com/en/stable/rop/srop.html
- tool: `ropper, ROPgadget, one_gadget`

# Formate String
- read stack:
	- %c to read a single character
	- %s to read a string
	- %p to read a pointer
	- %d, %i to read 4 byte integers (signed)
	- %o, %u, %x, %X to read 4 byte integers (unsigned)
- length modifiers
	- char 1B: hh
	- short 2B: h
	- normal 4 Byte
	- long 8B: l
	- long long 16B: ll
- `%41x` -> "erweitert" die Ausgabe auf 41 Zeichen -> es werden 41 Zeichen ausgegeben
- `%1$hhn` -> Schreibt ein Byte Anzahle aktuell ausgegebener Zeichen an die Stelle des Aktuellen Pointers
# Verschiedenes
- [RegisterMap Online](https://s3.amazonaws.com/media-p.slid.es/uploads/122159/images/1339091/x86_64-registers.png)
- [PWNGDB Cheat Sheet](https://pwndbg.re/CheatSheet.pdf) 
- https://github.com/niklasb/libc-database
- https://shell-storm.org/shellcode/index.html
- `call printf@plt -> jmp [rip + #offset] => rip + #offset -> printf@got.plt (r+w) -> printf in libc `
``` bash
checksec ./vuln
ropper -f ./vuln
ROPgadget
one_gadget
objdump -M intel -d vuln
readelf -s _libc.so.6 | grep "system"
```
- bytes in python
``` python
a = pwn.pack(0xf0)
b = pwn.pack(0x0f)

bytes(_a ^ _b for _a,_b in zip(a,b))
# b'\xff\x00\x00\x00'
bytes(_a & _b for _a,_b in zip(a,b))
# b'\x00\x00\x00\x00'
bytes(_a | _b for _a,_b in zip(a,b))
# b'\xff\x00\x00\x00'
```

# podman
```bash
podman compose up -d
podman ps -a
podman exec -ti container_123 /bin/bash
```
# pwngdb
- `set disassembly-flavor intel`
- `set {int}addr = val`
- `info proc mapping`