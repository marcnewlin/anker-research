#!/usr/bin/env python3

import struct
import crcmod
from PIL import Image
import numpy as np

telink_crc_fn = crcmod.predefined.mkCrcFun('crc-32')
gd32_crc_fn = crcmod.predefined.mkCrcFun('crc-32-mpeg')

with open("A1340_bao_V1.5.3.bin", "rb") as f:
  data = f.read()

# 
# parse the header
# - size of the Telink image
# - size of the GD32 image
# - CRC32 of each image, and a third CRC32 covering the concatenated Telink+GD32 images
#

header = data[:32]
values = list(struct.unpack(">IIIIIIII", header))
for v in values:
  print("0x%08x" % v)
gd32_fw_size = values[1]
telink_fw_size = values[2]

gd32_fw = data[32:32+gd32_fw_size]
telink_fw = data[32+gd32_fw_size:32+gd32_fw_size+telink_fw_size]

gd32_crc = gd32_crc_fn(gd32_fw)
telink_crc = telink_crc_fn(telink_fw)
image_crc = gd32_crc_fn(data[32:])

assert(gd32_crc == values[4])
assert(image_crc == values[3])
assert(telink_crc == 0xffffffff)

tail = data[32+gd32_fw_size+telink_fw_size:]
assert(len(tail) == 0)

#
# horizontally flip some sets of 0-9 digit bitmaps embedded in the GD32 image
# - only the 14x21 digits resulted in a change I could see in the UI
#

addrs = [

  # 8x12
  0x2ae70, # 0
  0x2af32, # 1 
  0x2aff4, # 2
  0x2b0b6, # 3
  0x2b178, # 4
  0x2b23a, # 5
  0x2b2fc, # 6
  0x2b3be, # 7
  0x2b480, # 8
  0x2b542, # 9

  # 14x21
  0x2ea9e, # 0
  0x2ecec, # 1 
  0x2ef3a, # 2
  0x2f188, # 3
  0x2f3d6, # 4
  0x2f624, # 5
  0x2f872, # 6
  0x2fac0, # 7
  0x2fd0e, # 8
  0x2ff5c, # 9

  # 53x69
  0x38cfe, # 0
  0x3a992, # 1 
  0x3c626, # 2
  0x3e2ba, # 3
  0x3ff4e, # 4
  0x41be2, # 5
  0x43876, # 6
  0x4550a, # 7
  0x4719e, # 8
  0x48e32, # 9
]

with open("gd32.bin", "wb") as f:
  f.write(gd32_fw)

for addr in addrs:
  width = gd32_fw[addr+0]
  height = gd32_fw[addr+1]
  assert(
    (width == 53 and height == 69) or 
    (width == 14 and height == 21) or
    (width == 8 and height == 12)
  )
  chunk = gd32_fw[addr+2:addr+2+(width * height * 2)]
  pattern = b"<" + b"H"*(int(len(chunk)/2))
  pixels = struct.unpack(pattern, chunk)
  flipped = []
  for x in range(height):
    row = pixels[x*width:(x+1)*width]
    row = row[::-1]
    flipped += row
  repacked = struct.pack(pattern, *flipped);

  gd32_fw = gd32_fw[:addr+2] + repacked + gd32_fw[addr+2+len(repacked):]

with open("gd32.patched.bin", "wb") as f:
  f.write(gd32_fw)

#
# change the product name in the Telink image
#

with open("telink.bin", "wb") as f:
  f.write(telink_fw)

print(len(telink_fw))
telink_fw_patched = telink_fw.replace(b"Prime", b"LOLOL")
telink_fw_patched = telink_fw_patched[:-4]
telink_fw_patched += struct.pack("<I", telink_crc_fn(telink_fw_patched) ^ 0xffffffff)

with open("telink.patched.bin", "wb") as f:
  f.write(telink_fw_patched)

#
# repack the patched DFU image and update the CRCs
#

values[4] = gd32_crc_fn(gd32_fw)
values[3] = gd32_crc_fn(gd32_fw + telink_fw_patched)

header_patched = struct.pack(">IIIIIIII", *values)

patched = header_patched + gd32_fw + telink_fw_patched
print(len(patched))
with open("A1340_bao_V1.5.3.patched.bin", "wb") as f:
  f.write(patched)
