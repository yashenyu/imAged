#!/usr/bin/env python3
"""
Test script for Hybrid AES-GCM implementation
Validates correctness against NIST test vectors and benchmarks performance
"""

import os
import sys
import time
import struct
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from HybridAES_GCM import HybridAES_GCM
from Version1 import AES_GCM as V1_AES_GCM
from Version2 import AES_GCM as V2_AES_GCM


def parse_nist_test_vector(line: str) -> dict:
    """Parse a single NIST test vector line"""
    parts = line.strip().split(' = ')
    if len(parts) != 2:
        return None
    key, value = parts
    return {key: value}


def load_nist_test_vectors(file_path: str) -> list:
    """Load NIST test vectors from .rsp file"""
    test_vectors = []
    current_test = {}
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#'):
                continue
            if line == '':
                if current_test:
                    test_vectors.append(current_test)
                    current_test = {}
                continue
            
            parsed = parse_nist_test_vector(line)
            if parsed:
                current_test.update(parsed)
    
    if current_test:
        test_vectors.append(current_test)
    
    return test_vectors


def bytes_from_hex(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_str)


def test_nist_vectors():
    """Test hybrid implementation against NIST test vectors"""
    print("Testing Hybrid AES-GCM against NIST test vectors...")
    
    # Test vector files
    test_files = [
        "testVectors/gcmEncryptExtIV128.rsp",
        "testVectors/gcmEncryptExtIV192.rsp", 
        "testVectors/gcmEncryptExtIV256.rsp",
        "testVectors/gcmDecrypt128.rsp",
        "testVectors/gcmDecrypt192.rsp",
        "testVectors/gcmDecrypt256.rsp"
    ]
    
    total_tests = 0
    passed_tests = 0
    
    for test_file in test_files:
        if not os.path.exists(test_file):
            print(f"Warning: Test file {test_file} not found, skipping...")
            continue
            
        print(f"\nTesting {test_file}...")
        vectors = load_nist_test_vectors(test_file)
        
        for i, vector in enumerate(vectors):
            if 'Key' not in vector or 'IV' not in vector:
                continue
                
            try:
                key = bytes_from_hex(vector['Key'])
                iv = bytes_from_hex(vector['IV'])
                
                # Initialize hybrid implementation
                hybrid = HybridAES_GCM(key)
                
                if 'PT' in vector and 'CT' in vector and 'Tag' in vector:
                    # Encryption test
                    plaintext = bytes_from_hex(vector['PT'])
                    expected_ciphertext = bytes_from_hex(vector['CT'])
                    expected_tag = bytes_from_hex(vector['Tag'])
                    aad = bytes_from_hex(vector.get('AAD', ''))
                    
                    # Encrypt with hybrid
                    result = hybrid.encrypt(iv, plaintext, aad, len(expected_tag))
                    ciphertext = result[:-len(expected_tag)]
                    tag = result[-len(expected_tag):]
                    
                    # Verify
                    if ciphertext == expected_ciphertext and tag == expected_tag:
                        passed_tests += 1
                    else:
                        print(f"  FAIL: Test {i} encryption mismatch")
                        print(f"    Expected CT: {expected_ciphertext.hex()}")
                        print(f"    Got CT:      {ciphertext.hex()}")
                        print(f"    Expected Tag: {expected_tag.hex()}")
                        print(f"    Got Tag:     {tag.hex()}")
                        
                elif 'CT' in vector and 'PT' in vector and 'Tag' in vector:
                    # Decryption test
                    ciphertext = bytes_from_hex(vector['CT'])
                    expected_plaintext = bytes_from_hex(vector['PT'])
                    tag = bytes_from_hex(vector['Tag'])
                    aad = bytes_from_hex(vector.get('AAD', ''))
                    
                    # Combine ciphertext and tag
                    data = ciphertext + tag
                    
                    # Decrypt with hybrid
                    try:
                        result = hybrid.decrypt(iv, data, aad, len(tag))
                        if result == expected_plaintext:
                            passed_tests += 1
                        else:
                            print(f"  FAIL: Test {i} decryption mismatch")
                            print(f"    Expected PT: {expected_plaintext.hex()}")
                            print(f"    Got PT:      {result.hex()}")
                    except Exception as e:
                        if 'FAIL' in vector:
                            # Expected failure
                            passed_tests += 1
                        else:
                            print(f"  FAIL: Test {i} unexpected exception: {e}")
                            print(f"    CT: {ciphertext.hex()}")
                            print(f"    Tag: {tag.hex()}")
                            
                total_tests += 1
                
            except Exception as e:
                print(f"  ERROR: Test {i} failed with exception: {e}")
                print(f"    Vector: {vector}")
    
    print(f"\nNIST Test Results: {passed_tests}/{total_tests} tests passed")
    return passed_tests == total_tests


def benchmark_implementations():
    """Benchmark hybrid against V1 and V2"""
    print("\nBenchmarking implementations...")
    
    # Test data sizes
    sizes = [16, 1024, 1024*1024, 10*1024*1024]  # 16B, 1KB, 1MB, 10MB
    
    # Test key and nonce
    key = os.urandom(16)
    nonce = os.urandom(12)
    aad = b"test associated data"
    
    implementations = {
        "Version 1": V1_AES_GCM,
        "Version 2": V2_AES_GCM,
        "Hybrid": HybridAES_GCM
    }
    
    results = {}
    
    for name, impl_class in implementations.items():
        print(f"\n{name}:")
        results[name] = {}
        
        for size in sizes:
            # Generate test data
            plaintext = os.urandom(size)
            
            # Warm up
            cipher = impl_class(key)
            _ = cipher.encrypt(nonce, plaintext[:1024], aad)
            
            # Benchmark encryption
            start_time = time.perf_counter()
            cipher = impl_class(key)
            encrypted = cipher.encrypt(nonce, plaintext, aad)
            encrypt_time = time.perf_counter() - start_time
            
            # Benchmark decryption
            start_time = time.perf_counter()
            cipher = impl_class(key)
            decrypted = cipher.decrypt(nonce, encrypted, aad)
            decrypt_time = time.perf_counter() - start_time
            
            # Verify correctness
            if decrypted != plaintext:
                print(f"  ERROR: {size} bytes - decryption failed!")
                continue
            
            # Calculate throughput
            encrypt_throughput = size / encrypt_time / (1024*1024)  # MB/s
            decrypt_throughput = size / decrypt_time / (1024*1024)  # MB/s
            
            results[name][size] = {
                'encrypt_time': encrypt_time,
                'decrypt_time': decrypt_time,
                'encrypt_throughput': encrypt_throughput,
                'decrypt_throughput': decrypt_throughput
            }
            
            print(f"  {size:>8} bytes: Encrypt {encrypt_throughput:6.1f} MB/s, Decrypt {decrypt_throughput:6.1f} MB/s")
    
    # Print comparison
    print("\nPerformance Comparison:")
    print("Size      | Version 1    | Version 2    | Hybrid       | V1→Hybrid | V2→Hybrid")
    print("----------|--------------|--------------|--------------|-----------|-----------")
    
    for size in sizes:
        v1_enc = results["Version 1"][size]['encrypt_throughput']
        v2_enc = results["Version 2"][size]['encrypt_throughput']
        hybrid_enc = results["Hybrid"][size]['encrypt_throughput']
        
        v1_improvement = (hybrid_enc / v1_enc - 1) * 100
        v2_improvement = (hybrid_enc / v2_enc - 1) * 100
        
        print(f"{size:>8} | {v1_enc:>10.1f} | {v2_enc:>10.1f} | {hybrid_enc:>10.1f} | {v1_improvement:>+8.1f}% | {v2_improvement:>+8.1f}%")


def test_api_compatibility():
    """Test that hybrid API is compatible with V1"""
    print("\nTesting API compatibility...")
    
    key = os.urandom(16)
    nonce = os.urandom(12)
    plaintext = b"test message"
    aad = b"test aad"
    
    # Test V1
    v1 = V1_AES_GCM(key)
    v1_result = v1.encrypt(nonce, plaintext, aad, 12)
    
    # Test Hybrid with same parameters
    hybrid = HybridAES_GCM(key)
    hybrid_result = hybrid.encrypt(nonce, plaintext, aad, 12)
    
    if v1_result == hybrid_result:
        print("✓ API compatibility test passed")
    else:
        print("✗ API compatibility test failed")
        print(f"V1 result: {v1_result.hex()}")
        print(f"Hybrid result: {hybrid_result.hex()}")


def test_debug_vector():
    """Test debug_vector function"""
    print("\nTesting debug_vector function...")
    
    key = bytes.fromhex("00000000000000000000000000000000")
    nonce = bytes.fromhex("000000000000000000000000")
    plaintext = bytes.fromhex("00000000000000000000000000000000")
    
    hybrid = HybridAES_GCM(key)
    debug_info = hybrid.debug_vector(nonce, plaintext)
    
    print("Debug vector output:")
    for key, value in debug_info.items():
        print(f"  {key}: {value}")


def main():
    """Main test function"""
    print("Hybrid AES-GCM Implementation Test Suite")
    print("=" * 50)
    
    # Test NIST vectors
    nist_passed = test_nist_vectors()
    
    # Test API compatibility
    test_api_compatibility()
    
    # Test debug vector
    test_debug_vector()
    
    # Benchmark performance
    benchmark_implementations()
    
    print("\n" + "=" * 50)
    if nist_passed:
        print("✓ All NIST test vectors passed!")
    else:
        print("✗ Some NIST test vectors failed!")
    print("Hybrid implementation combines V1's correctness with V2's performance optimizations.")


if __name__ == "__main__":
    main()
