# ImAged .ttl File Format Specification

## Header Layout

| Offset | Length | Field                    | Type     | Description                                                             |
|--------|--------|--------------------------|----------|-------------------------------------------------------------------------|
| 0x00   | 4      | **Magic**                | 4 bytes  | ASCII “IMAG”                                                            |
| 0x04   | 1      | **Version**              | uint8    | Format version (start at `1`)                                           |
| 0x05   | 3      | **Flags / Reserved**     | 3 bytes  | Reserved for future use (set to `0`)                                    |
| 0x08   | 8      | **Creation Timestamp**   | uint64BE | UNIX epoch seconds when file was created                                |
| 0x10   | 8      | **Expiration Timestamp** | uint64BE | UNIX epoch seconds when file should expire                              |
| 0x18   | 4      | **Payload Length**       | uint32BE | Number of bytes in the (yet‑to‑be‑encrypted) payload                    |
| 0x1C   | N      | **Payload**              | —        | QOI‑compressed image data (for now, unencrypted)                        |
| …      | …      | **(future extension)**   | —        | Space reserved for encryption IV, auth‑tag, etc. (in later iterations)  |

## Notes

- **Big‑endian** for all multi‑byte integers.  
- In this first iteration the “Payload” is just raw QOI bytes.  
- Later we’ll wrap all bytes from offset 0x08 through the end of “Payload” in AES‑GCM.
