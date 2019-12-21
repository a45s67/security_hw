# security_hw
修computer security的一個紀錄

<br>
pwn - cheatsheet <br>
<br>
dump section : readelf -S 'filename' <br>
only dump library got : objdump -R 'filename' <br>
disasm binary : objdump -d 'filename' <br>
check protect : checksec 'filename' <br>
rop gadget : ROPgadget --binary 'filename' [ --only "pop|ret" ]  <br>
file : file 'filename' <br>
<br>

pwntools

l = ELF("./libc") <br>
func addr : l.sym.system  or l.sym.__malloc_hook <br>
find str addr : l.search("/bin/sh").next() <br>

p = process("./binary") or remote("pwnaddr.url",port) <br>
p.sendafter("recv str", payload) <br>

for leak libc: u64(p.recv(6)+"\0\0") <br>
              (sometimes need p.recvlines(line_num)) or p.recvuntil("recv_str") to align to leak addr ) <br>
              
trick : find one_gadget from libc  <br>
        one_gadget after double free <br>
