import json
import re
import struct
from enum import IntEnum
from Crypto.Cipher import AES
from functools import reduce
import operator


class Command(IntEnum):
  GetBatteryMetrics = 0
  InitiateSession = 1
  NegotiateCapabilities = 3
  SetCapabilities = 5
  GetChargingMetrics = 14
  GetSessionKey = 34
  SetBoundAccount = 35
  GetDeviceInfo = 41
  GetUpdateState = 137
  StartUpdate = 138
  UpdateChunkResponse = 139
  SendUpdateChunk = 140
  FinalizeUpdate = 141


class Parameter:
  def __init__(self, name: str, index: int, length: int, value: any, value_packed: bytes):
    self.name = name
    self.index = index
    self.length = length
    self.value = value
    self.value_packed = value_packed
  def pack(self):
    return struct.pack("BB", self.index, self.length) + self.value_packed

class UInt8(Parameter):
  def __init__(self, name: str, index: int, value: int = 0):
    Parameter.__init__(self, name, index, 1, value, struct.pack("<B", value))
  def from_bytes(name: str, index: int, raw: bytes):
    assert(len(raw) == 1)
    return UInt8(name, index, struct.unpack("<B", raw)[0])

class UInt16(Parameter):
  def __init__(self, name: str, index: int, value: int = 0):
    Parameter.__init__(self, name, index, 2, value, struct.pack("<H", value))
  def from_bytes(name: str, index: int, raw: bytes):
    assert(len(raw) == 2)
    return UInt16(name, index, struct.unpack("<H", raw)[0])
  
class UInt32(Parameter):
  def __init__(self, name: str,  index: int, value: int = 0):
    Parameter.__init__(self, name, index, 4, value, struct.pack("<I", value))
  def from_bytes(name: str, index: int, raw: bytes):
    assert(len(raw) == 4)
    return UInt32(name, index, struct.unpack("<I", raw)[0])
  
class Bytes(Parameter):
  def __init__(self, name: str, index: int, value: bytes = b""):
    Parameter.__init__(self, name, index, len(value), value, bytes(value))
  def from_bytes(name: str, index: int, raw: bytes):
    return Bytes(name, index, raw)
  
class BleMac(Parameter):
  def __init__(self, name: str, index: int, value: bytes = b""):
    Parameter.__init__(self, name, index, len(value), value, bytes(value))
  def from_bytes(name: str, index: int, raw: bytes):
    return BleMac(name, index, raw)  
  
class ParameterEncoder(json.JSONEncoder):
  def default(self, p):
    d = {
      "name": p.name,
      "type": p.__class__.__name__,
      "index": p.index,
      "value": p.value,
      "length": p.length,
    }
    if isinstance(p, UInt8) or isinstance(p, UInt16) or isinstance(p, UInt32):
      return d
    elif isinstance(p, BleMac):
      d["value"] = ":".join("%02x"%c for c in p.value)
      return d
    elif isinstance(p, Bytes):
      d["value"] = list(p.value)
      d["_hex"] = bytearray(p.value).hex()
      d["_ascii"] = re.sub(rb"\W", b".", p.value).decode("ascii")
      return d
    elif isinstance(p, bytearray):
      d["value"] = list(p)
      d["_hex"] = p.hex()
      d["_ascii"] = re.sub(rb"\W", b".", p).decode("ascii")
      return d
    raise RuntimeError("Unhandled type in JSON encoder %s" % p.__class__._name__)


class Package:
  def __init__(self, command: int, flags: int, params: list[Parameter]):
    self.command = command
    self.flags = flags
    self.params =  { p.index:  p for p in params }
    self.status_code = None

  def print(self):
    print("Package")
    print(json.dumps(self.__dict__, indent=2, cls=ParameterEncoder))
    print("")

  def pack(self, key:bytes=None, iv:bytes=None, flags1=0):
    params_packed = b"".join(p.pack() for p in self.params.values())
    print(bytearray(params_packed).hex())
    if key and iv:
      p = params_packed
      if len(p) % 16 != 0:
        p += b"\x06" * (16 - (len(p) % 16))
      cipher = AES.new(key, AES.MODE_CBC, iv)
      params_packed = cipher.encrypt(p)
    # magic
    pdu = b"\xff\x09"
    # length
    pdu += struct.pack("<H", len(params_packed) + 10)
    # protocol version?
    pdu += b"\x03"
    # ???
    pdu += bytes([flags1])
    # flags
    pdu += struct.pack(">H", self.flags)
    # command
    pdu += struct.pack("<B", self.command)
    # payload
    pdu += params_packed
    # checksum
    pdu += struct.pack("<B", reduce(operator.xor, pdu))
    return pdu
  def pack_encrypted(self, key, iv):
    return self.pack(key, iv)
  def parse_encrypted(self, pdu: bytes, key: bytes, iv: bytes):
    return self.parse(pdu, key, iv)

  def parse(self, pdu: bytes, key:bytes=None, iv:bytes=None):
    # checksum
    assert(reduce(operator.xor, pdu) == 0)
    # magic
    assert(pdu[:2] == b"\xff\x09")
    # length
    length = struct.unpack("<H", pdu[2:4])[0]
    assert(length == len(pdu))
    # protocol version?
    assert(pdu[4] == 3)
    # ???
    assert(pdu[5] in [0, 1])
    # flags
    flags = struct.unpack(">H", pdu[6:8])[0]
    # payload
    params_packed = pdu[9:-1]

    if key and iv:
      assert(len(params_packed) % 16 == 0)
      cipher = AES.new(key, AES.MODE_CBC, iv)
      params_packed = cipher.decrypt(params_packed)

    print(params_packed)
    print(bytearray(params_packed).hex())

    command = pdu[8]
    assert(command == self.command)

    response = (flags & 0x08) == 0x08
    if response:
      self.status_code = params_packed[0]
      assert(self.status_code == 0)
      params_packed = params_packed[1:]

    raw = params_packed
    print(bytearray(raw).hex())
    while len(raw):
      t, l, v = raw[0], raw[1], raw[2:2+raw[1]]
      if t < 0xa1 and key and iv: # padding
        break
      self.params[t] = self.params[t].__class__.from_bytes(self.params[t].name, t, v)
      raw = raw[2+l:]
