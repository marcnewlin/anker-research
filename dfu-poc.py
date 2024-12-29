#!/usr/bin/env python3

import argparse
import asyncio
import re
import struct
import sys
import time
from uuid import uuid4
from bleak import BleakClient
from enum import Flag
from ble_types import *

WRITE_UUID = "22150002-4002-81c5-b46e-cf057c562025"
READ_UUID = "22150003-4002-81c5-b46e-cf057c562025"

def log(msg):
  sys.stdout.write("[%d] " % time.time())
  sys.stdout.write(msg)
  sys.stdout.write("\n")
  sys.stdout.flush()

class DD(dict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

class MessageFlags(Flag):
  _None = 0x0000
  Unknown1 = 0x0001
  _0x0002 = 0x0002
  Unknown4 = 0x0004
  Response = 0x0008
  _0x0010 = 0x0010
  _0x0020 = 0x0020
  Encrypted = 0x0040
  _0x0080 = 0x0080
  Unknown = 0x0100
  _0x0200 = 0x0200
  _0x0400 = 0x0400
  _0x0800 = 0x0800
  HandshakeDone = 0x1000
  _0x2000 = 0x2000
  _0x4000 = 0x4000
  _0x8000 = 0x8000  

class Client:

  def __init__(self, addr, verbose=True):
    self.client = BleakClient(addr)
    self.read_queue = asyncio.Queue()
    self.verbose = verbose

  async def __aenter__(self):
    log("connecting")
    await self.client.connect()
    log("connected")
    await self.client.start_notify(READ_UUID, self.notification_handler)
    await asyncio.sleep(0.25)
    return self

  async def __aexit__(self, exc_type, exc, tb):
    await self.client.disconnect()

  async def notification_handler(self, sender, data):
    await self.read_queue.put(data)

  async def send_command(self, command, parameters, response_parameters, flags:MessageFlags=0, flags1=0, encrypted=False, timeout=1, response_command=None):

    if response_command is None:
      response_command = command

    # MessageFlags.Unknown is set on all observed messages
    flags = MessageFlags(flags) | MessageFlags.Unknown

    if encrypted:
      flags |= MessageFlags.Encrypted

    aes_key = self.aes_key if encrypted else None
    aes_iv = self.aes_iv if encrypted else None

    req_pkg = Package(command, flags.value, parameters)
    pdu = req_pkg.pack(aes_key, aes_iv, flags1=flags1)

    # send the command to the battery
    log("[TX] %s" % bytearray(pdu).hex())
    await self.client.write_gatt_char(WRITE_UUID, pdu)
    
    # read the response
    start = time.time()
    response = None
    while (time.time() - start) < timeout:
      await asyncio.sleep(0.1)
      if not self.read_queue.empty():
        response = await self.read_queue.get()
        log("[RX] %s" % bytearray(response).hex())
        break
    if response is None:
      raise TimeoutError("command timed out")

    res_pkg = Package(response_command, flags.value, response_parameters)
    res_pkg.parse(response, aes_key, aes_iv)
    return res_pkg
  
  def compute_session_key(self, seed=b"\x01\x02\x03\x04\x05\x05"):
    ts_bytes = struct.pack("<I", self.timestamp)
    user_id = self.user_id[:16].encode()
    key = bytearray([0]*16)
    for x in range(16):
      key[x] = (((ts_bytes[x%4] ^ user_id[x]) + seed[x % 6]) * 3) & 0xff
    return key

  def load_session(self, path=".session"):
    with open(".session", "r") as f:
      data = json.loads(f.read())
    self.ble_mac = ":".join("%02x" % c for c in bytearray.fromhex(data["battery_mac"]))
    self.user_id = data["user_id"]
    self.timestamp = data["timestamp"]
    self.battery_sn = data["battery_sn"]
    self.aes_key = self.compute_session_key()
    self.aes_iv = self.battery_sn.encode()

  def save_session(self, path=".session"):
    session = {
      "user_id": self.user_id,
      "timestamp": self.timestamp,
      "battery_sn": self.battery_sn,
      "battery_mac": self.ble_mac,
    }
    with open(path, "w") as f:
      f.write(json.dumps(session))

  async def test_session(self):
    try:
      await self.get_battery_metrics()
      return True
    except TimeoutError:
      return False

  async def init_session(self, user_id:str=str(uuid4()), timestamp=int(time.time())):

    # uuid hex string
    # - normally comes from an Anker API request
    # - used in both BLE and web API requests
    self.user_id = user_id

    # UTC timestamp of the first message in the session handshake
    # - this probably exists for metrics/logging
    # - used in both BLE and web API requests
    self.timestamp = timestamp

    # AES key used to encrypt the data portion of Anker's BLE messages
    self.aes_key = user_id.encode()[:16]
    self.aes_iv = None
    log("user_id=%s" % self.user_id)
    log("timestamp=%d" % self.timestamp)

    #
    # handshake 1 of 6
    # - user_id is a UUID hex string
    # - initial AES key is first 16 bytes of user_id
    #
    res = await self.send_command(Command.InitiateSession, [
      UInt32("timestamp", 0xa1, self.timestamp),
      Bytes("user_id", 0xa2, self.user_id.encode()),
    ], [
      UInt8("param_1", 0xa1),
    ])
    if self.verbose:
      res.print()

    #
    # handshake 2 of 6
    # - unknown parameters 0xa3, 0xa4
    #
    res = await self.send_command(Command.NegotiateCapabilities, [
      UInt32("timestamp", 0xa1, self.timestamp),
      Bytes("user_id", 0xa2, self.user_id.encode()),
      UInt8("param_1", 0xa3, 0x20), # session timeout?
      UInt16("param_2", 0xa4, 0x00f0), # MTU?
    ], [
      UInt8("param_1", 0xa1),
      UInt16("param_2", 0xa2),
    ])
    if self.verbose:
      res.print()

    #
    # handshake 3 of 6
    # - read battery identifiers
    #
    res = await self.send_command(Command.GetDeviceInfo, [
      UInt32("timestamp", 0xa1, self.timestamp),
      Bytes("user_id", 0xa2, self.user_id.encode()),
    ], [
      UInt8("param_1", 0xa1),
      Bytes("model", 0xa2),
      Bytes("version", 0xa3),
      Bytes("serial_number", 0xa4),
      BleMac("ble_mac", 0xa5),
    ])
    if self.verbose:
      res.print()
    battery_sn = res.params[0xa4].value.decode()
    self.battery_sn = battery_sn
    self.ble_mac = bytearray(res.params[0xa5].value).hex()
    self.aes_iv = res.params[0xa4].value

    #
    # handshake 4 of 6
    # - unknown parameters 0xa2, 0xa3, 0xa4
    #
    res = await self.send_command(Command.SetCapabilities, [
      UInt32("timestamp", 0xa1, self.timestamp),
      Bytes("user_id", 0xa2, self.user_id.encode()),
      UInt8("param_1", 0xa3, 0x20), # session timeout?
      UInt16("param_2", 0xa4, 0x00f0), # MTU?
      UInt8("param_3", 0xa5, 0x02), # ???
    ], [
      # no response parameters
    ])
    if self.verbose:
      res.print()

    #
    # handshake 5 of 6
    # - send timezone config to battery
    # - battery replies with session key
    # - session key is (utc_offset bytes repeated 4 times) ^ (battery serial)
    #
    utc_offset = 18000 # timezone UTC offset in seconds
    posix_timezone = b"EST5EDT,M3.2.0,M11.1.0" # posix timezone string
    res = await self.send_command(Command.GetSessionKey, [
      UInt32("timestamp", 0xa1, self.timestamp),
      Bytes("user_id", 0xa2, self.user_id.encode()),
      UInt32("utc_offset", 0xa3, utc_offset),
      Bytes("posix_timezone", 0xa5, posix_timezone),
    ], [
      Bytes("session_key", 0xa1)
    ], encrypted=True)
    if self.verbose:
      res.print()
    self.aes_key = res.params[0xa1].value

    #
    # handshake 6 of 6
    # - send battery serial
    # - encrypted with session key
    #
    res = await self.send_command(Command.SetBoundAccount, [
      UInt32("timestamp", 0xa1, self.timestamp),
      Bytes("user_id", 0xa2, self.user_id.encode()),
      Bytes("battery_sn", 0xa3, battery_sn.encode()),
    ], [
      # no response parameters
    ], encrypted=True)
    if self.verbose:
      res.print()

    self.save_session()

  async def push_dfu(self, path="A1340_bao_V1.5.3.bin"):
    with open(path, "rb") as f:
      data = f.read()

    header = data[:32]

    '''
    observed request parameters for the 1.5.3 update:

    a1 01 21
    a2 05 03 e4d80600 
    a3 03 02 0000
    a4 15 04 0313400000056b2000016da4e60f4daa75f9aae6
    fe 05 03 a9276767
    '''

    res = await self.send_command(Command.StartUpdate, [
      UInt8("param_1", 0xa1, 0x21),
      Bytes("image_size", 0xa2, struct.pack("<BI", 3, len(data))),
      Bytes("param_2", 0xa3, b"\x02\x00\x00"),
      Bytes("image_header", 0xa4, b"\x04" + header[:20]),
      Bytes("param_3", 0xfe, struct.pack("<BI", 3, self.timestamp)),
    ], [
      Bytes("param_1", 0xa1),
      Bytes("chip_num", 0xa2),
      Bytes("reboot_time", 0xa3),
      Bytes("sub_package_size", 0xa4),
      Bytes("start_position", 0xa5),
      Bytes("sub_package_count", 0xa6),
    ], 
      encrypted=True, 
      flags=0x1140,
      timeout=10,
    )
    res.print()

    image = data
    while len(image):
      chunk = image[:200]
      image = image[200:]

      if len(image) == 0:

        if len(chunk) < 200:
          pad_len = 200 - len(chunk)
          chunk += b"\x00" * pad_len

        res = await self.send_command(Command.SendUpdateChunk, [
          UInt8("param_1", 0xa1, 0x21), # a10121 (3)
          Bytes("param_2", 0xa2, b"\x00\x00\x00\x00\x00"), # a2050000000000 (7)
          Bytes("chunk_data", 0xa3, b"\x00" + chunk),
          Bytes("param_3", 0xfe, struct.pack("<BI", 3, self.timestamp)),
        ], [
          Bytes("param_1", 0xa1),
          Bytes("chip_num", 0xa2),
        ], 
          encrypted=True, 
          flags=0x1140,
          response_command=Command.FinalizeUpdate,
        )
        res.print()

      else:

        res = await self.send_command(Command.SendUpdateChunk, [
          UInt8("param_1", 0xa1, 0x21), # a10121 (3)
          Bytes("param_2", 0xa2, b"\x00\x00\x00\x00\x00"), # a2050000000000 (7)
          Bytes("chunk_data", 0xa3, b"\x00" + chunk),
          Bytes("param_3", 0xfe, struct.pack("<BI", 3, self.timestamp)),
        ], [
          Bytes("param_1", 0xa1),
          Bytes("chip_num", 0xa2),
        ], 
          encrypted=True, 
          flags=0x1140,
          response_command=Command.UpdateChunkResponse,
        )
        res.print()
    

  async def get_battery_metrics(self, timeout=1):

    #
    # read battery metrics
    # - BLE command 0x00 might be a passthrough to the MCU
    # - additional fields are described in app_log.log (flutter log)
    res = await self.send_command(Command.GetBatteryMetrics, [
      UInt8("param_1", 0xa1, 0x21),
      Bytes("param_2", 0xfe, struct.pack("<BI", 3, self.timestamp)),
    ], [
      *[Bytes("param_0x%02x" % c, c) for c in range(0xa1, 0xb6)]
    ], 
      encrypted=True, 
      flags=MessageFlags.HandshakeDone|MessageFlags.Unknown|MessageFlags.Unknown1|MessageFlags.Unknown4, 
      timeout=timeout,
      flags1=0,
    )
    res.print()

    def parse_port_status(raw):
      port = DD()
      port.status = raw[0]
      port.volts = struct.unpack("<H", raw[3:5])[0] / 10.
      port.amps = struct.unpack("<H", raw[5:7])[0] / 10.
      port.watts = port.volts * port.amps
      return port
    
    info = DD()
    info.charging_ports = DD()

    # 0xa1

    # 0xa2
    info.remaining_time_hms = "%d:%d:%d" % (res.params[0xa2].value[2], res.params[0xa2].value[3], res.params[0xa2].value[4])
    info.battery_health = res.params[0xa2].value[5]
    info.battery_level = float("{}.{}".format(res.params[0xa2].value[8], res.params[0xa2].value[9]))
    info.cycle_count = struct.unpack("<H", res.params[0xa2].value[6:8])[0]

    # 0xa3
    info.base_indicator_light_switch_status = res.params[0xa3].value[0]

    # 0xa4
    info.charging_ports.usb_c_1 = parse_port_status(res.params[0xa4].value)

    # 0xa5
    info.charging_ports.usb_c_2 = parse_port_status(res.params[0xa5].value)

    # 0xa6
    info.charging_ports.usb_a = parse_port_status(res.params[0xa6].value)

    # 0xa7
    info.charging_ports.pogo = parse_port_status(res.params[0xa7].value)

    # 0xa8
    # 0xa9
    # 0xaa
    # 0xab
    # 0xac

    # 0xad
    info.firmware_version = ".".join(str(res.params[0xad].value[1]))

    # 0xae
    # 0xaf
    # 0xb0
    # 0xb1
    # 0xb2

    # 0xb3
    info.temp_celsius = res.params[0xb3].value[1]
    info.temp_farenheit = res.params[0xb3].value[2]

    # what units are these field?
    # - maybe total input/output watt-hours or something?
    # - 24-bit integers
    # - "total input power" and "total output power" (from translated app_log.log)
    raw = res.params[0xb4].value
    info.total_input_power = raw[1] + (raw[2] * 0x100) + (raw[3] * 0x10000)
    info.total_output_power = raw[4] + (raw[5] * 0x100) + (raw[6] * 0x10000)

    # 0xb5

    print(json.dumps(info, indent=2))

  async def get_charging_metrics(self):

    # read charging metrics (subset of battery metrics)
    res = await self.send_command(Command.GetChargingMetrics, [
      UInt8("param_1", 0xa1, 0x31),
      Bytes("param_2", 0xfe, struct.pack("<BI", 3, self.timestamp)),
    ], [
      Bytes("param_0xa1", 0xa1),
      Bytes("param_0xa2", 0xa2),
      Bytes("param_0xa3", 0xa3),
      Bytes("param_0xa4", 0xa4),
      Bytes("param_0xa5", 0xa5),
      Bytes("param_0xa6", 0xa6),
      Bytes("param_0xa7", 0xa7),
      Bytes("param_0xa8", 0xa8),
      Bytes("param_0xa9", 0xa9),
      Bytes("param_0xfe", 0xfe),
    ], encrypted=True, flags=0x1145, flags1=1)
    res.print()    

    # update_state = res.params[0xa2].value[1]
    # min_battery = res.params[0xa3].value[1]
    # print("update_state=%d" % update_state)
    # print("min_battery=%d" % min_battery)

  async def get_update_state(self):

    # read battery metrics
    # - BLE command 0x00 might be a passthrough to the MCU
    # - additional fields are described in app_log.log (flutter log)
    res = await self.send_command(Command.GetUpdateState, [
      UInt8("param_1", 0xa1, 0x21),
      Bytes("param_2", 0xfe, struct.pack("<BI", 3, self.timestamp)),
    ], [
      *[Bytes("param_0x%02x" % c, c) for c in range(0xa1, 0xa4)]
    ], encrypted=True, flags=0x1140)
    # res.print()    

    update_state = res.params[0xa2].value[1]
    min_battery = res.params[0xa3].value[1]
    print("update_state=%d" % update_state)
    print("min_battery=%d" % min_battery)

async def main(addr, path="A1340_bao_V1.5.3.bin"):
  import os

  async with Client(addr) as client:
  
    # if os.path.exists(".session"):
    #   client.load_session()
    #   if not await client.test_session():
    #     await client.init_session()
    # else:
    #   await client.init_session()

    await client.init_session()
    # await client.get_battery_metrics()
    # await client.get_charging_metrics()

    await client.get_update_state()
    await client.push_dfu(path)


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--addr", "-a", type=str, default="F4:9D:8A:36:79:30", help="BLE address in the format XX:XX:XX:XX:XX:XX")
  args = parser.parse_args()

  if not re.fullmatch(r"([a-f0-9]{2}\:){5}[a-f0-9]{2}", args.addr, flags=re.IGNORECASE):
    raise ValueError("Invalid BLE address '{}'".format(args.addr))

  asyncio.run(main(args.addr, "A1340_bao_V1.5.3.patched.bin"))
