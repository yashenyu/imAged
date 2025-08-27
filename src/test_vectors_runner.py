import argparse
import os
import re
import sys
import json
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

try:
    from .aes_gcm import AES_GCM, InvalidTagException, InvalidInputException
except Exception:
    sys.path.append(os.path.dirname(__file__))
    from aes_gcm import AES_GCM, InvalidTagException, InvalidInputException


def _hex_to_bytes(value: str) -> bytes:
    value = value.strip()
    if value == '' or value == '00' * 0:
        return b''
    return bytes.fromhex(value)


def _parse_rsp_file(path: str) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
    """
    Parse a NIST-style .rsp file.

    Returns:
      header: dictionary of section-level parameters like Taglen, Keylen, etc.
      vectors: list of dictionaries per test with keys among:
               Count, Key, IV, PT, CT, AAD, Tag, Result/FAIL
    """
    header: Dict[str, str] = {}
    vectors: List[Dict[str, str]] = []
    current: Dict[str, str] = {}

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith('#'):
                if not line and current:
                    vectors.append(current)
                    current = {}
                continue

            if line.startswith('[') and line.endswith(']'):
                content = line[1:-1]
                if '=' in content:
                    key, value = [p.strip() for p in content.split('=', 1)]
                    header[key] = value
                else:
                    header[content] = ''
                continue

            if '=' in line:
                key, value = [p.strip() for p in line.split('=', 1)]
                current[key] = value
                continue

            if line.upper() in ('FAIL', 'PASS'):
                current['Result'] = line.upper()

        if current:
            vectors.append(current)

    return header, vectors


def _infer_mode_from_filename(filename: str) -> str:
    name = filename.lower()
    if 'decrypt' in name:
        return 'decrypt'
    if 'encrypt' in name:
        return 'encrypt'
    return 'decrypt'


def _run_vector(mode: str, header: Dict[str, str], vector: Dict[str, str], impl: str = 'custom', cipher: Optional[AES_GCM] = None) -> Tuple[bool, Optional[str], Optional[Dict[str, str]]]:
    """
    Execute single vector. Returns (passed, error_message_if_any)
    """
    key_hex = vector.get('Key', '')
    iv_hex = vector.get('IV', '') or vector.get('Nonce', '')
    aad_hex = (
        vector.get('AAD', '') or vector.get('Adata', '') or vector.get('A', '')
    )
    pt_hex = (
        vector.get('PT', '') or vector.get('Plaintext', '') or vector.get('P', '')
    )
    ct_hex = (
        vector.get('CT', '') or vector.get('Ciphertext', '') or vector.get('C', '')
    )
    tag_hex = vector.get('Tag', '') or vector.get('TAG', '') or vector.get('T', '')

    try:
        key = _hex_to_bytes(key_hex)
        iv = _hex_to_bytes(iv_hex)
        aad = _hex_to_bytes(aad_hex)
        pt = _hex_to_bytes(pt_hex)
        ct = _hex_to_bytes(ct_hex)
        tag = _hex_to_bytes(tag_hex)
    except ValueError as ex:
        return False, f"Hex parse error: {ex}", None

    tag_len_bytes: Optional[int] = None
    if tag:
        tag_len_bytes = len(tag)
    else:
        tag_len_bits: Optional[int] = None
        for k in ('Taglen', 'TagLen', 'TcLen', 'Tlen', 'TLen'):
            if k in header:
                try:
                    tag_len_bits = int(header[k])
                    break
                except ValueError:
                    pass
        if tag_len_bits is None and 'Tlen' in vector:
            try:
                tag_len_bits = int(vector['Tlen'])
            except ValueError:
                pass
        if tag_len_bits is not None:
            tag_len_bytes = tag_len_bits // 8
    if tag_len_bytes is None:
        tag_len_bytes = 16
    if tag_len_bytes not in (16, 15, 14, 13, 12, 8, 4):
        tag_len_bytes = max(4, min(16, tag_len_bytes))

    if mode == 'decrypt' and (not tag) and ct and len(ct) >= tag_len_bytes:
        tag = ct[-tag_len_bytes:]
        ct = ct[:-tag_len_bytes]

    if impl == 'custom':
        try:
            # REUSE existing cipher if provided, otherwise create new one
            if cipher is None:
                cipher = AES_GCM(key)
                cipher.set_enforce_iv_uniqueness(False)
                
                if 'IVlen' in header:
                    cipher._expected_iv_len = int(header['IVlen'])
            
        except InvalidInputException as ex:
            return False, f"Invalid key: {ex}", None

    expected_fail = vector.get('Result', '').upper() == 'FAIL' or vector.get('FAIL', '').upper() == 'TRUE'

    try:
        if mode == 'encrypt':
            if impl == 'custom':
                out = cipher.encrypt(iv, pt, aad, tag_len_bytes=tag_len_bytes)
                out_ct = out[:-tag_len_bytes] if tag_len_bytes else out
                out_tag = out[-tag_len_bytes:] if tag_len_bytes else b''
            else:
                encryptor = Cipher(algorithms.AES(key), modes.GCM(iv, min_tag_length=tag_len_bytes), backend=default_backend()).encryptor()
                if aad:
                    encryptor.authenticate_additional_data(aad)
                out_ct = encryptor.update(pt) + encryptor.finalize()
                out_tag = encryptor.tag[:tag_len_bytes]

            if ct and out_ct != ct:
                dbg = None
                if impl == 'custom':
                    dbg = cipher.debug_vector(iv, pt, aad, tag_len_bytes=tag_len_bytes)
                return False, "CT mismatch", dbg
            if tag and out_tag != tag:
                dbg = None
                if impl == 'custom':
                    dbg = cipher.debug_vector(iv, pt, aad, tag_len_bytes=tag_len_bytes)
                return False, "Tag mismatch", dbg
            if expected_fail:
                return False, "Expected FAIL but encryption succeeded", None
            return True, None, None

        if impl == 'custom':
            combined = ct + (tag if tag else b'')
            pt_out = cipher.decrypt(iv, combined, aad, tag_len_bytes=tag_len_bytes)
        else:
            if not tag:
                return False, f"Missing Tag for decrypt (ct={len(ct)} bytes, aad={len(aad)} bytes, tag_len={tag_len_bytes})", None
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            if aad:
                decryptor.authenticate_additional_data(aad)
            pt_out = decryptor.update(ct) + decryptor.finalize()

        if expected_fail:
            return False, "Expected FAIL but decryption succeeded", None
        if pt and pt_out != pt:
            dbg = None
            if impl == 'custom':
                dbg = cipher.debug_vector(iv, pt, aad, tag_len_bytes=tag_len_bytes)
            return False, "PT mismatch", dbg
        return True, None, None

    except InvalidTagException:
        if expected_fail:
            return True, None, None
        dbg = None
        if impl == 'custom':
            dbg = cipher.debug_vector(iv, pt, aad, tag_len_bytes=tag_len_bytes)
        return False, "Invalid tag", dbg
    except Exception as ex:
        if expected_fail:
            return True, None, None
        dbg = None
        if impl == 'custom':
            try:
                dbg = cipher.debug_vector(iv, pt, aad, tag_len_bytes=tag_len_bytes)
            except Exception:
                dbg = None
        return False, f"Decrypt error: {ex}", dbg


def _find_rsp_files(dir_path: str) -> List[str]:
    results: List[str] = []
    for root, _, files in os.walk(dir_path):
        for filename in files:
            if filename.lower().endswith('.rsp'):
                results.append(os.path.join(root, filename))
    results.sort()
    return results


def run_rsp_file(path: str, live: bool = True, limit: Optional[int] = None, impl: str = 'custom') -> Tuple[int, int, List[str]]:
    filename = os.path.basename(path)
    mode = _infer_mode_from_filename(filename)
    header, vectors = _parse_rsp_file(path)

    total = 0
    passed = 0
    failed_cases: List[str] = []

    num_vectors = len(vectors)
    max_count_width = len(str(num_vectors)) if num_vectors > 0 else 1

    # CREATE SINGLE CIPHER INSTANCE FOR ALL VECTORS
    cipher = None
    if impl == 'custom' and vectors:
        # Get key from first vector to create cipher once
        first_key = _hex_to_bytes(vectors[0].get('Key', ''))
        if first_key:
            cipher = AES_GCM(first_key)
            cipher.set_enforce_iv_uniqueness(False)
            if 'IVlen' in header:
                cipher._expected_iv_len = int(header['IVlen'])

    # For each test vector:
    cipher_cache: Dict[str, AES_GCM] = {}
    for idx, vec in enumerate(vectors):
        if limit is not None and total >= limit:
            break
        total += 1
        cnt = vec.get('Count', str(idx))
        if live:
            prefix = f"[{idx + 1:{max_count_width}d}/{num_vectors}] {filename} Count={cnt} ... "
            print(prefix, end='', flush=True)
        
        # PASS THE REUSED CIPHER INSTANCE
        key_hex = vec.get('Key', '')
        if key_hex not in cipher_cache:
            # Create NEW cipher with THIS key
            key_bytes = _hex_to_bytes(key_hex)
            cipher = AES_GCM(key_bytes)  # ← Different key = different cipher!
            cipher_cache[key_hex] = cipher
        else:
            # Reuse existing cipher with SAME key
            cipher = cipher_cache[key_hex]
        
        ok, err, dbg = _run_vector(mode, header, vec, impl=impl, cipher=cipher)
        
        if ok:
            passed += 1
            if live:
                print("OK")
        else:
            failed_cases.append(f"{filename}#Count={cnt}: {err}")
            if live:
                print(f"FAIL ({err})")
                details = {
                    'header': header,
                    'vector': vec,
                    'impl': impl,
                    'error': err
                }
                if dbg:
                    details['debug'] = dbg
                print(json.dumps(details, indent=2))

    return total, passed, failed_cases


def run_rsp_suite(dir_path: str, live: bool = True, limit: Optional[int] = None, impl: str = 'custom') -> int:
    total = 0
    passed = 0
    failed_cases: List[str] = []

    files = _find_rsp_files(dir_path)
    if not files:
        print("No .rsp files found.")
        return 1

    for path in files:
        if live:
            print(f"\nRunning: {os.path.basename(path)}")
        t, p, fails = run_rsp_file(path, live=live, limit=limit, impl=impl)
        total += t
        passed += p
        failed_cases.extend(fails)

    print(f"\nVectors: {total}, Passed: {passed}, Failed: {total - passed}")
    if failed_cases:
        print("First 20 failures:")
        for msg in failed_cases[:20]:
            print(f" - {msg}")
    return 0 if total == passed else 1


def main():
    parser = argparse.ArgumentParser(description='Run AES-GCM against NIST .rsp test vectors')
    parser.add_argument('--dir', default=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'testVectors'),
                        help='Directory containing .rsp files')
    parser.add_argument('--file', help='Run a single .rsp file (path or filename under --dir)')
    parser.add_argument('--interactive', action='store_true', help='Interactive mode: choose one .rsp to run')
    parser.add_argument('--no-live', action='store_true', help='Disable per-test live output')
    parser.add_argument('--limit', type=int, default=None, help='Limit number of vectors per file')
    parser.add_argument('--impl', choices=['custom', 'crypto', 'hybrid'], default='custom', help='Implementation to test: custom (V1), crypto (backend), or hybrid (V1+V2)')
    args = parser.parse_args()

    live = not args.no_live

    if args.file:
        path = args.file
        if not os.path.isabs(path) and not os.path.exists(path):
            candidate = os.path.join(args.dir, args.file)
            if os.path.exists(candidate):
                path = candidate
        if not os.path.exists(path):
            print(f"File not found: {path}")
            raise SystemExit(1)
        print(f"Running single file: {os.path.basename(path)}")
        total, passed, failures = run_rsp_file(path, live=live, limit=args.limit, impl=args.impl)
        print(f"\nVectors: {total}, Passed: {passed}, Failed: {total - passed}")
        if failures:
            print("First 20 failures:")
            for msg in failures[:20]:
                print(f" - {msg}")
        raise SystemExit(0 if total == passed else 1)

    if args.interactive:
        files = _find_rsp_files(args.dir)
        if not files:
            print("No .rsp files found.")
            raise SystemExit(1)
        print("Select a .rsp file to run:")
        for idx, path in enumerate(files):
            print(f"  [{idx+1}] {os.path.basename(path)}")
        try:
            choice = int(input("Enter number: ").strip())
        except Exception:
            print("Invalid input.")
            raise SystemExit(1)
        if choice < 1 or choice > len(files):
            print("Choice out of range.")
            raise SystemExit(1)
        path = files[choice - 1]
        print(f"Running: {os.path.basename(path)}")
        total, passed, failures = run_rsp_file(path, live=live, limit=args.limit, impl=args.impl)
        print(f"\nVectors: {total}, Passed: {passed}, Failed: {total - passed}")
        if failures:
            print("First 20 failures:")
            for msg in failures[:20]:
                print(f" - {msg}")
        raise SystemExit(0 if total == passed else 1)

    exit_code = run_rsp_suite(args.dir, live=live, limit=args.limit, impl=args.impl)
    raise SystemExit(exit_code)


if __name__ == '__main__':
    main()

# To Run: python -m src.test_vectors_runner --dir ./testVectors --impl custom

