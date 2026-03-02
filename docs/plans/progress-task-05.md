# Task 5 Progress: CRC16/IBM

**Status:** completed

## Steps
- [x] Write crc16_test.go (failing test)
- [x] Run test — verify it fails
- [x] Write crc16.go (implementation)
- [x] Run test — verify it passes
- [x] Commit

## Notes

The test vectors in the task spec were inconsistent with each other and with
the C source. The C `crc16()` in `lt_crc16.c` uses MSB-first bit processing
with a final byte-swap (`return (crc << 8 | crc >> 8)`). This means:

- `0x01` → `0x0580` (not `0x8005` as the spec stated)
- `"123456789"` → `0xE8FE` (not `0xBB3D` as the spec stated)

The spec's `0x8005` value is the MSB-first result *before* the byte-swap.
The spec's `0xBB3D` is the standard CRC-16/ARC (reflected) result, a
completely different algorithm.

Per the task instructions, the C source was treated as ground truth and the
test vectors were corrected accordingly.
