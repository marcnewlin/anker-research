#!/usr/bin/env python3

from PIL import Image
import os
import numpy as np

os.system("mkdir -p images")

with open("gd32.bin", "rb") as f:
  data = bytearray(f.read())

#
# offsets to some bitmap images embedded in the GD32 firmware
# - some sort of 16-bit RGB encoding
# - each image has a simple 2-byte width:height header
# - each pixel is 16-bits
# - maybe RGB565 encoding?
# - the addrs are all +0x2000 from their locations in the .bin file
#   (I think the bootloader takes up the first 0x2000 bytes, so the
#   addrs displayed in Ghidra are offset 0x2000 from the start of the
#   .bin file, and I was mostly looking for bitmaps by scrolling through 
#   non-disassembled code in Ghidra and rendering byte sequences to 
#   images files on disk to see if anything looked like letters or numbers)
# - in some cases, there are runs of contiguous bitmaps embedded in
#   the GD32 firmware, and in other cases they appear at a fixed cadence
#   with spacing inbetween
#

# start addresses of some contiguous runs of bitmaps
# - bitmap width/height varies, with no spacing between subsequent images
offsets = [0x25858, 0x25922, 0x2f676, 0x3464e, 0x37954]
offsets += [0x2dfda]
offsets += [0x321aa]

# addresses of some images spaced evently at 1162 bytes
# - the images are generally smaller than 1162 bytes with 0x00 bytes inbetween
offsets += [0x4cc50, 0x4d0da, 0x4d564, 0x4d9ee, 0x4de78, 0x4e302, 0x4e78c, 0x4ec16, 0x4f0a0, 0x4f52a, 0x4f9b4, 0x4fe3e, 0x502c8, 0x50752, 0x50bdc, 0x51066, 0x514f0, 0x5197a, 0x51e04, 0x5228e, 0x52718, 0x5302c, 0x534b6, 0x53940, 0x53dca, 0x54254, 0x546de, 0x54b68, 0x54ff2, 0x5547c, 0x55906, 0x55d90, 0x5621a, 0x566a4, 0x56b2e, 0x56fb8, 0x57442, 0x578cc, 0x57d56, 0x581e0]
offsets = list(set(offsets))
for _offset in offsets:
  offset = _offset - 0x2000

  # look for up to 100 contiguous images starting at this address
  for x in range(10):
    bpp = 2
    width = data[offset+0]
    height = data[offset+1]
    if width == 0 or height == 0:
      print("ZERO WIDTH HEIGHT @ %s" % hex(offset+0x2000))
      break
    chunk = data[offset+2:offset+2+width*height*2]
    print(hex(offset+0x2000), width, height)
    try:
      pixels = np.reshape(bytearray(chunk), (height, width, bpp))
    except:
      print("FAIL @ %s" % hex(offset+0x2000))
      break

    # render the image to a .png file
    img = Image.fromarray(pixels)
    img.save("images/%s.png" % hex(offset))
    offset = offset+2+width*height*2
