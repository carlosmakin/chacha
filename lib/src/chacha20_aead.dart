import 'dart:typed_data';

import 'package:chacha/src/chacha20.dart';
import 'package:chacha/src/poly1305.dart';
import 'package:chacha/utilities/secure_equality.dart';

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

/// Generates a Poly1305 key using the ChaCha20 block function with a zero counter.
/// Accepts a 256-bit key and a 96-bit nonce.
Uint8List poly1305KeyGen(Uint8List key, Uint8List nonce) {
  return chacha20Block(key.buffer.asUint32List(), nonce.buffer.asUint32List(), 0).sublist(0, 32);
}

/// Encrypts and authenticates data using ChaCha20-Poly1305 AEAD scheme as per RFC 8439.
/// Accepts key, nonce, data, and optional additional authenticated data (AAD).
Uint8List chacha20Poly1305Encrypt(
  Uint8List key,
  Uint8List nonce,
  Uint8List data, [
  Uint8List? aad,
]) {
  // Generate the Poly1305 one-time-key using the ChaCha20 block function with a counter of 0
  final Uint8List otk = poly1305KeyGen(key, nonce);

  // Encrypt the data using ChaCha20
  final Uint8List ciphertext = chacha20(key, nonce, data, 1);

  // Create the Poly1305 message for MAC tag calculation
  final Uint8List macData = _buildMacData(ciphertext, aad);

  // Calculate the MAC tag using Poly1305
  final Uint8List tag = poly1305Mac(otk, macData);

  // The output from the AEAD is the concatenation of:
  // - A ciphertext of the same length as the plaintext
  // - A 128-bit tag, which is the output of the Poly1305 function
  final Uint8List result = Uint8List(ciphertext.length + 16);
  result.setAll(0, ciphertext);
  result.setAll(ciphertext.length, tag);

  return result;
}

/// Decrypts and verifies data encrypted with ChaCha20-Poly1305 AEAD scheme.
/// Accepts key, nonce, encrypted data, and optional AAD; throws if verification fails.
Uint8List chacha20Poly1305Decrypt(
  Uint8List key,
  Uint8List nonce,
  Uint8List data, [
  Uint8List? aad,
]) {
  if (data.length < 16) throw Exception('Invalid encrypted data length.');

  // Generate the Poly1305 one-time-key using the ChaCha20 block function with a counter of 0
  final Uint8List otk = poly1305KeyGen(key, nonce);

  // Separate the encrypted data and the MAC tag
  final Uint8List ciphertext = Uint8List.view(data.buffer, 0, data.length - 16);
  final Uint8List tag = Uint8List.view(data.buffer, data.length - 16);

  // Recreate the Poly1305 message for MAC tag verification
  final Uint8List macData = _buildMacData(ciphertext, aad);

  // Calculate and verify the MAC tag
  if (!secureEquals(tag, poly1305Mac(otk, macData))) {
    throw Exception('MAC verification failed.');
  }

  // Decrypt the data using ChaCha20
  return chacha20(key, nonce, ciphertext);
}
