# Overview

This repository contains PoC code and logs/notes related to my research into the Anker A1340 power bank.

Vulnerabilities in the BLE protocol and DFU mechanism can be exploited to push malicious firmware images to the Telink BLE SoC and GD32 MCU.

## Disclosure Timeline

- January 2025 - disclosed the bugs to Anker
- May 2025 - Anker completed the fix, adding an ECDSA signature to the DFU process, and introducing a PKI-authenticated variant of the BLE protocol
- August 2025 - public disclosure to add to the parallel-discovery corpus: https://github.com/atc1441/Anker_Prime_BLE_hacking

## Files

ble_types.py
- BLE command codes and command packing/parsing logic

dfu-poc.py
- DFU client that can send original or modified firmware to the battery
- performs the connection handshake to establish a "session key" with the battery
- functions to get charging-port status and battery metrics from the A1340
- RE work has mostly been copying-and-pasting `app_log.log` into the Google translate

patch-poc.py
- script to patch `A1340_bao_V1.5.3.bin`
- patches Telink image to change the device name from `Anker Prime Power Bank` to `Anker LOLOL Power Bank`
- patches the GD32 image to horizontally flip several sizes of digit bitmaps embedded in the firmware image; so far I've only seen one of the digit-sets result in changes in the UI
- generates `A!340_bao_V1.5.3.patched.bin` that can be used with `dfu-poc.py`

extract-bitmaps.py
- script to extract some 16 bit-per-pixel bitmap images embedded in the firmware
- this is the result of eyeballing some non-disassembled bytes in the GD32 firmware in Ghidra and making some guesses

ghidra-projects/gigadevice-mcu.gzf
ghidra-projects/telink-ble-soc.gzf
- ghidra projects for the firmwares
- both are a little inconsistent but make some reasonable guesses
- the GD32 project only has a few functions labelled
- Telink project has a lot more coverage, but I think I conflated some BLE and UART functions
- Telink project uses this processor plugin for their TC32 ISA: https://github.com/trust1995/Ghidra_TELink_TC32.git

app_log.log
- flutter app log that pretty verbosely describes the BLE and cloud-API protocols
