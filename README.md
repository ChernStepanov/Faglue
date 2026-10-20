# Faglue

*This is an educational project for me to get rid of vibecoding and gain some knowledge about PE structures. Not pretending to be something helpful!*

> **Some serious words** *(I have a task for thinking readers - paste them yourself so I don't have to. Preferably something about "next-gen threat intelligence").*

---

## Why does this exist?

Because asking ChatGPT to write a Python script that imports pefile teaches you nothing. 

**Faglue** is a zero-dependency static PE inspector written in pure C with the help of Google and Microsoft documentation. It structurizes the bytes, checks that the data don't exceed file boundaries and flags the classic tricks malware authors love.

## What it does

* **Parses the header:** Walks DOS_HEADER, jumps over the DOS stub via e_lfanew and parses COFF and Section headers directly from the file stream.
* **Detects RWX:** Translates raw Characteristics bitmasks into human-readable permissions and yells at you when a section is both writable and executable.
* **Spots runtime code initialization:** Flags sections with empty RawData and non-zero VirtualSize, where unpackers like UPX dump their actual code.
* **Calculates entropy:** Computes Shannon per section to catch compressed or encrypted payloads.
* **Tries to be secure itself:** Rejects truncated headers, catches PointerToRawData out of bounds offsets and avoids integer overflows when calculating section boundaries.

---

## Build & Usage

No CMake, no external libraries, just gcc and libm:

```bash
make
./faglue <path_to_pe_file.exe>