import 'dart:typed_data';

import 'package:chacha/src/chacha20.dart';
import 'package:chacha/src/poly1305.dart';

Uint8List _buildMacData(Uint8List bytes, Uint8List? aad) {
  aad ??= Uint8List(0);

  final int byteLen = bytes.length;
  final int bytePadLen = (16 - (byteLen % 16)) % 16;

  final int aadLen = aad.length;
  final int aadPadLen = (16 - (aadLen % 16)) % 16;

  final Uint8List macData = Uint8List(
    (aadLen + aadPadLen) + (byteLen + bytePadLen) + 16,
  );

  macData.setAll(0, aad);
  macData.setAll((aadLen + aadPadLen), bytes);
  macData.setAll(
    (aadLen + aadPadLen) + (byteLen + bytePadLen),
    (ByteData(16)
          ..setUint64(0, aadLen, Endian.little)
          ..setUint64(8, byteLen, Endian.little))
        .buffer
        .asUint8List(),
  );

  return macData;
}

/// Compares two lists of integers (`left` and `right`) for equality in a constant-time manner.
/// This approach mitigates timing attacks in cryptographic contexts by ensuring the
/// execution time depends only on the length of the lists, not the data they contain.
///
/// Returns `true` if the lists are equal, `false` otherwise.
bool _secureEquals(List<int> left, List<int> right) {
  // Return false immediately if lengths differ, as the lists can't be equal.
  if (left.length != right.length) return false;

  int result = 0;
  // Compare elements using XOR; accumulate any differences in `result`.
  for (int i = 0; i < left.length; i++) {
    result |= (left[i] ^ right[i]);
  }

  // If `result` is 0, all elements matched; otherwise, at least one pair differed.
  return result == 0;
}

/// ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) as defined in RFC 8439.
///
/// Combining ChaCha20 cipher and Poly1305 MAC, this class offers symmetric encryption ensuring
/// data confidentiality, integrity, and authenticity. It is optimal for high-security and
/// high-performance environments in symmetric data encryption and authentication.
abstract class Chacha20Poly1305 {
  /// Generates a Poly1305 key using the ChaCha20 block function with a zero counter as per RFC 8439.
  ///
  /// Accepts a 256-bit key and a 96-bit nonce.
  static Uint8List generateKey(Uint8List key, Uint8List nonce) {
    return chacha20Block(key.buffer.asUint32List(), nonce.buffer.asUint32List(), 0).sublist(0, 32);
  }

  /// Encrypts and authenticates data using ChaCha20-Poly1305 AEAD scheme as per RFC 8439.
  ///
  /// Accepts a 256-bit key and a 96-bit nonce, data, and optional additional authenticated data (AAD).
  static Uint8List encrypt(Uint8List key, Uint8List nonce, Uint8List data, [Uint8List? aad]) {
    // Generate the Poly1305 one-time-key using the ChaCha20 block function with a counter of 0
    final Uint8List otk = generateKey(key, nonce);

    // Encrypt the data using ChaCha20
    final Uint8List ciphertext = Chacha20.encrypt(key, nonce, data, 1);

    // Create the Poly1305 message for MAC tag calculation
    final Uint8List macData = _buildMacData(ciphertext, aad);

    // Calculate the MAC tag using Poly1305
    final Uint8List tag = Poly1305.computeMac(otk, macData);

    // The output from the AEAD is the concatenation of:
    // - A ciphertext of the same length as the plaintext
    // - A 128-bit tag, which is the output of the Poly1305 function
    final Uint8List result = Uint8List(ciphertext.length + 16);
    result.setAll(0, ciphertext);
    result.setAll(ciphertext.length, tag);

    return result;
  }

  /// Decrypts and verifies data encrypted with ChaCha20-Poly1305 AEAD scheme as per RFC 8439.
  ///
  /// Accepts a 256-bit key and a 96-bit nonce, data, and optional additional authenticated data (AAD).
  /// Throws if verification fails.
  static Uint8List decrypt(Uint8List key, Uint8List nonce, Uint8List data, [Uint8List? aad]) {
    if (data.length < 16) throw Exception('Invalid encrypted data length.');

    // Generate the Poly1305 one-time-key using the ChaCha20 block function with a counter of 0
    final Uint8List otk = generateKey(key, nonce);

    // Separate the encrypted data and the MAC tag
    final Uint8List ciphertext = Uint8List.view(data.buffer, 0, data.length - 16);
    final Uint8List tag = Uint8List.view(data.buffer, data.length - 16);

    // Recreate the Poly1305 message for MAC tag verification
    final Uint8List macData = _buildMacData(ciphertext, aad);

    // Calculate and verify the MAC tag
    if (!_secureEquals(tag, Poly1305.computeMac(otk, macData))) {
      throw Exception('MAC verification failed.');
    }

    // Decrypt the data using ChaCha20
    return Chacha20.decrypt(key, nonce, ciphertext);
  }
}
