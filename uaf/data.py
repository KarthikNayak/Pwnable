import struct

test = struct.pack("I", 0x00401550 - 0x08) * 1
with open('sutract', 'wb') as f:
    f.write(test)
    test = struct.pack("I", 0x00) * 1
    f.write(test)
