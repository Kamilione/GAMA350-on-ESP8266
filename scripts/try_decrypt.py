#!/usr/bin/env python3
"""Offline decryption/IV finder for Elgama GAMA 350 (Stoen Operator) telegrams.

The GAMA 350 transmits an *empty* system title in its DLMS ciphering header,
but the meter may use its real, serial-derived system title as the first half
of the AES-128-GCM IV. This script tests the likely candidates against one
captured telegram body so the right `system_title:` value can be found on a
PC in seconds instead of reflashing the ESP for every guess.

Requirements:
    pip install pycryptodome

Usage:
    python3 try_decrypt.py --key <32-hex EK> --ak <32-hex AK> \
        --serial <meter serial> --body "<hex dump of the telegram body>"

    # --ak verifies the GCM tag: a VERIFIED hit proves EK + system title are
    # correct. Without --ak the script falls back to a printable-text guess.

    # or test one explicit candidate:
    python3 try_decrypt.py --key <32-hex EK> --title 454C470000BC614E \
        --body "<hex dump>"

    # last-ditch: brute-force every 3-letter FLAG code + serial vs the GCM tag
    python3 try_decrypt.py --key <EK> --ak <AK> --serial <serial> --brute \
        --body "<hex dump>"

The body is everything between the empty line and the '!' footer of the raw
telegram; for the GAMA 350 it is 564 bytes and starts with: 00 82 02 30 30.
--body accepts either a plain hex dump, or raw ESPHome log lines from the
component's VERBOSE dump ('BODY[000]: 0082...') pasted as-is - the log
prefixes are stripped and only the first complete telegram is used.

A correct key + IV combination produces readable ASCII OBIS lines and is
reported as MATCH. If no candidate matches, swap in the other key (AK/EK
labels are sometimes reversed) and run again.
"""

import argparse
import itertools
import re
import string
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("pycryptodome is required: pip install pycryptodome")

GCM_TAG_LEN = 12


def tag_ok(cipher_key, iv, aad, ciphertext, tag):
    """Return True if the GCM tag verifies for these inputs."""
    cipher = AES.new(cipher_key, AES.MODE_GCM, nonce=iv, mac_len=GCM_TAG_LEN)
    cipher.update(aad)
    cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return True
    except ValueError:
        return False


def _bcd5(serial):
    """Last 5 bytes of the serial in packed BCD, left-padded with zero bytes.
    Handles any digit count (pads odd-length to even before hex decoding)."""
    digits = str(serial)
    if len(digits) % 2:
        digits = "0" + digits
    return bytes.fromhex(digits)[-5:].rjust(5, b"\x00")


def serial_tails(serials):
    """5-byte serial-derived tails for a list of serial numbers, in the
    encodings DLMS meters commonly use for the back half of a system title."""
    out = []
    seen = set()
    for serial in serials:
        encs = {
            "binary-BE": serial.to_bytes(5, "big") if serial < 2 ** 40 else None,
            "binary-LE": serial.to_bytes(5, "little") if serial < 2 ** 40 else None,
            "binary-4B": bytes(1) + serial.to_bytes(4, "big") if serial < 2 ** 32 else None,
            "BCD": _bcd5(serial),
            "ASCII": str(serial).encode()[-5:].rjust(5, b"0"),
        }
        for enc_label, tail in encs.items():
            if tail is None or len(tail) != 5:
                continue
            key = bytes(tail)
            if key not in seen:
                seen.add(key)
                out.append((f"serial {serial} {enc_label}", tail))
    return out


def brute_force_flag(orderings, serials, frame_counter, ciphertext, tag):
    """Last-ditch search: every 3-letter uppercase manufacturer FLAG code
    plus each serial/encoding tail, tag-verified. Returns (label, cipher_key,
    system_title) on the first hit, or None.
    """
    tails = serial_tails(serials)
    total = 26 ** 3 * len(tails) * sum(1 for o in orderings if o[2] is not None)
    print(f"Brute-forcing {total} flag/serial/key combinations "
          f"({len(tails)} serial-tail variants)...")
    tried = 0
    for order_label, cipher_key, order_aad in orderings:
        if order_aad is None:
            continue  # tag check needs AK; skip decrypt-only ordering
        for letters in itertools.product(string.ascii_uppercase, repeat=3):
            flag = "".join(letters).encode()
            for enc_label, tail in tails:
                tried += 1
                if tried % 50000 == 0:
                    print(f"  ...{tried}/{total}")
                title = flag + tail
                if tag_ok(cipher_key, title + frame_counter, order_aad,
                          ciphertext, tag):
                    return (f"{order_label}, FLAG '{flag.decode()}' + {enc_label}",
                            cipher_key, title)
    return None


def hex_bytes(text):
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(cleaned) % 2:
        sys.exit("Error: odd number of hex digits after stripping non-hex characters.")
    return bytes.fromhex(cleaned)


def body_bytes(text):
    """Parse the --body input.

    Accepts either a plain hex dump, or raw ESPHome log lines containing the
    component's VERBOSE dump ('... BODY[032]: 0082...'). For log lines, only
    the hex payload after 'BODY[nnn]:' is used, and parsing stops when the
    offset wraps back to a smaller value (i.e. the next telegram starts), so
    several telegrams' worth of log can be pasted as-is.
    """
    picked = []
    last_offset = -1
    for line in text.splitlines():
        m = re.search(r"BODY\[(\d+)\]:\s*([0-9A-Fa-f]+)", line)
        if not m:
            continue
        offset = int(m.group(1))
        if offset <= last_offset:
            break  # next telegram started
        last_offset = offset
        picked.append(m.group(2))
    if picked:
        return bytes.fromhex("".join(picked))
    return hex_bytes(text)


def printable_ratio(data):
    ok = sum(1 for b in data if 0x20 <= b < 0x7F or b in (0x0D, 0x0A, 0x09))
    return ok / max(1, len(data))


def candidates(serials, explicit):
    """Yield (label, 8-byte system title) candidates for the IV."""
    yield "all-zeros (component default)", bytes(8)
    if explicit is not None:
        yield "explicit --title", explicit
    # ASCII title guesses derived from the meter's identification header.
    yield "ASCII 'EGM5G35' + NUL", b"EGM5G35\x00"
    yield "ASCII '/EGM5G35'[:8]", b"/EGM5G35"
    # DLMS convention: 3-letter manufacturer FLAG code + 5-byte serial tail.
    # Elgama appears as both "ELG" (FLAG registry) and "EGM" (DSMR ident);
    # a few neighbours are tried too since the registry code is uncertain.
    flags = (b"ELG", b"EGM", b"ELS", b"ELT", b"GAM")
    for enc_label, tail in serial_tails(serials):
        for flag in flags:
            yield f"{flag.decode()} + {enc_label}", flag + tail
        yield f"zeros + {enc_label}", bytes(3) + tail
    # Full 8-byte system titles built purely from the serial (no FLAG prefix):
    # an 8-digit serial is exactly 8 ASCII bytes, plus left/right-aligned
    # binary and BCD forms in the full 8-byte field.
    for serial in serials:
        ascii8 = str(serial).encode()
        if len(ascii8) == 8:
            yield f"serial {serial} ASCII (full 8 bytes)", ascii8
        digits = str(serial)
        if len(digits) % 2:
            digits = "0" + digits
        bcd = bytes.fromhex(digits)
        if len(bcd) <= 8:
            yield f"serial {serial} BCD left-aligned", bcd.ljust(8, b"\x00")
            yield f"serial {serial} BCD right-aligned", bcd.rjust(8, b"\x00")
        if serial < 2 ** 64:
            yield f"serial {serial} binary BE (8 bytes)", serial.to_bytes(8, "big")
            yield f"serial {serial} binary LE (8 bytes)", serial.to_bytes(8, "little")


def main():
    parser = argparse.ArgumentParser(
        description="Test system-title candidates against a captured GAMA 350 telegram body."
    )
    parser.add_argument("--key", required=True, help="encryption key EK (32 hex chars)")
    parser.add_argument("--ak", help="authentication key AK (32 hex chars). When given, the GCM tag is verified - a VERIFIED hit proves the key+system-title are correct.")
    parser.add_argument("--body", required=True, help="telegram body as hex (564 bytes, starts with 00 82 02 30 30)")
    parser.add_argument("--serial", help="meter serial number(s) from the nameplate (digits; comma-separate several, e.g. the serial and the type/full numbers)")
    parser.add_argument("--title", help="explicit 16-hex system title candidate to test")
    parser.add_argument("--brute", action="store_true",
                        help="if no candidate verifies, brute-force every 3-letter FLAG code + serial against the GCM tag (needs --ak and --serial)")
    args = parser.parse_args()

    key = hex_bytes(args.key)
    if len(key) != 16:
        sys.exit(f"Error: key must be 16 bytes (32 hex chars), got {len(key)} bytes.")

    ak = None
    if args.ak:
        ak = hex_bytes(args.ak)
        if len(ak) != 16:
            sys.exit(f"Error: --ak must be 16 bytes (32 hex chars), got {len(ak)} bytes.")

    body = body_bytes(args.body)
    if not body:
        sys.exit("Error: empty body.")

    if body[0] == 0x00:
        st_len = 1  # empty system title
    elif body[0] == 0xDB:
        st_len = body[1] + 2  # explicit system title in the frame
    else:
        sys.exit(f"Error: body must start with 00 or DB, got {body[0]:02X}.")

    if len(body) < st_len + 8 + GCM_TAG_LEN:
        sys.exit(f"Error: body too short ({len(body)} bytes).")

    len_info = (body[st_len + 1] << 8) | body[st_len + 2]
    sc_byte = body[st_len + 3]
    frame_counter = bytes(body[st_len + 4 : st_len + 8])
    ct_len = len_info - 5 - GCM_TAG_LEN
    ciphertext = bytes(body[st_len + 8 : st_len + 8 + ct_len])
    tag = bytes(body[st_len + 8 + ct_len : st_len + 8 + ct_len + GCM_TAG_LEN])
    if len(ciphertext) != ct_len or len(tag) != GCM_TAG_LEN:
        sys.exit(
            f"Error: body holds {len(ciphertext)} ciphertext bytes but LEN_INFO "
            f"implies {ct_len}. Incomplete capture?"
        )

    serials = []
    if args.serial:
        for part in args.serial.split(","):
            digits = re.sub(r"\D", "", part)
            if digits:
                serials.append(int(digits))
    explicit = hex_bytes(args.title) if args.title else None
    if explicit is not None and len(explicit) != 8:
        sys.exit("Error: --title must be 8 bytes (16 hex chars).")

    print(f"SC=0x{sc_byte:02X}, LEN_INFO={len_info}, ciphertext={ct_len} bytes, "
          f"frame counter={frame_counter.hex().upper()}, tag={tag.hex().upper()}")
    if ak is not None:
        print("AK supplied: GCM tag is verified (VERIFIED = key + system title proven correct).\n")
    else:
        print("No --ak: judging by printable ratio only. Pass --ak for a definitive check.\n")

    # When AK is supplied, test both key role assignments: the labels EK/AK
    # are sometimes reversed, and the tag check is the only definitive way to
    # tell. cipher_key runs the GCM cipher; the other key goes into the AAD.
    if ak is not None:
        orderings = [
            ("--key as EK, --ak as AK", key, bytes([sc_byte]) + ak),
            ("--key as AK, --ak as EK", ak, bytes([sc_byte]) + key),
        ]
    else:
        orderings = [("decrypt-only (no tag check)", key, None)]

    matches = []
    for order_label, cipher_key, order_aad in orderings:
        print(f"=== {order_label} ===")
        for label, title in candidates(serials, explicit):
            iv = title + frame_counter
            verified = False
            if order_aad is not None:
                cipher = AES.new(cipher_key, AES.MODE_GCM, nonce=iv, mac_len=GCM_TAG_LEN)
                cipher.update(order_aad)
                plain = cipher.decrypt(ciphertext)
                try:
                    cipher.verify(tag)
                    verified = True
                except ValueError:
                    verified = False
            else:
                plain = AES.new(cipher_key, AES.MODE_GCM, nonce=iv).decrypt(ciphertext)
            ratio = printable_ratio(plain[:64])
            hit = verified or (order_aad is None and ratio >= 0.9)
            if hit:
                matches.append((cipher_key, title))
            marker = "VERIFIED" if verified else ("MATCH ->" if hit else " " * 8)
            print(f"{marker} {label:32s} system_title={title.hex().upper()}  printable={ratio:4.0%}  {plain[:40]!r}")
        print()

    # Last-ditch brute force over all 3-letter FLAG codes + serial.
    if not matches and args.brute:
        if ak is None or not serials:
            print("\n--brute needs both --ak and --serial.")
        else:
            print()
            hit = brute_force_flag(orderings, serials, frame_counter, ciphertext, tag)
            if hit:
                label, cipher_key, title = hit
                print(f"\nVERIFIED via brute force: {label}")
                matches.append((cipher_key, title))

    if matches:
        winning_key, winning_title = matches[0]
        print("\nAdd to your YAML under dsmr_custom: :")
        print(f'  decryption_key: "{winning_key.hex().upper()}"')
        if winning_title != bytes(8):
            print(f'  system_title: "{winning_title.hex().upper()}"')
        else:
            print("  # system_title not needed (zeros is the default)")
    elif ak is not None:
        print(
            "\nNo system-title candidate verified against the GCM tag"
            + (" (including the full 3-letter FLAG brute force)" if args.brute else "")
            + ". Since the tag check uses BOTH keys, this means EK and/or AK is "
            "wrong for this meter (typo, swapped with another meter's keys, or "
            "wrong serial)"
            + ("." if args.brute else ", OR the system title is non-standard - "
               "re-run with --brute to search all FLAG codes.")
            + " Re-check the keys against the Stoen document and the serial "
            "against the nameplate."
        )
    else:
        print(
            "\nNo candidate produced readable text. Re-run with --ak <AK> for a "
            "definitive tag check, double-check the keys/serial, or verify the "
            "keys were issued for this meter's serial number."
        )


if __name__ == "__main__":
    main()
