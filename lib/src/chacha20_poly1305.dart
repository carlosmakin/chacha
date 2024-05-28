import 'dart:convert';
import 'dart:typed_data';

import 'package:chacha/src/chacha20.dart';
import 'package:chacha/src/poly1305.dart';

/// ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) (RFC 8439).
///
/// Combines the symmetric ChaCha20 cipher and Poly1305 MAC to provide encryption along with data integrity
/// and authenticity verification. This class is ideal for high-security scenarios, ensuring confidentiality,
/// integrity, and authenticity in encryption and authentication processes.
class ChaCha20Poly1305 extends Converter<List<int>, List<int>> {
  const ChaCha20Poly1305._(this._aad, this._chacha20, this._poly1305, this._encrypt);

  /// Converts and authenticates data using ChaCha20-Poly1305 AEAD scheme as per RFC 8439.
  ///
  /// Accepts a 256-bit key and a 96-bit nonce, data, and optional additional authenticated data (AAD).
  factory ChaCha20Poly1305(Uint8List? aad, Uint8List key, Uint8List nonce, bool encrypt) {
    if (key.length != 32) throw ArgumentError('Invalid key');
    if (nonce.length != 12) throw ArgumentError('Invalid nonce');

    return ChaCha20Poly1305._(
      aad,
      ChaCha20(key, nonce, 1),
      Poly1305(generateKey(key, nonce)),
      encrypt,
    );
  }

  final bool _encrypt;
  final Uint8List? _aad;
  final ChaCha20 _chacha20;
  final Poly1305 _poly1305;

  @override
  Uint8List convert(List<int> input) {
    if (_encrypt && input.length < 16) throw Exception('Invalid data length.');
    final int inputLen = input.length;
    final int outputLen = _encrypt ? input.length + 16 : input.length - 16;

    final Uint8List data = Uint8List(outputLen);

    if (_encrypt) {
      data.setRange(0, inputLen, _chacha20.convert(input));
      data.setRange(
        inputLen,
        outputLen,
        _poly1305.convert(
          _buildMacData(_aad, data.buffer.asUint8List(0, inputLen)),
        ),
      );
      return data;
    }

    data.setRange(0, outputLen, input);
    final List<int> tag = input.sublist(outputLen, inputLen);
    if (!verifyMac(_poly1305.convert(_buildMacData(_aad, data)), tag)) {
      throw Exception('MAC verification failed.');
    }
    return _chacha20.convert(data);
  }

  /// Generates a Poly1305 key using the ChaCha20 block function with a zero counter as per RFC 8439.
  ///
  /// Accepts a 256-bit key and a 96-bit nonce.
  static Uint8List generateKey(Uint8List key, Uint8List nonce) {
    final Uint8List keystream = Uint8List(64);
    final Uint32List state = initState(key.buffer.asUint32List(), nonce.buffer.asUint32List());
    chacha20Block(0, keystream, state, Uint32List(16));
    return keystream.sublist(0, 32);
  }

  /// Verifies the integrity and authenticity of a message using its Poly1305 MAC.
  ///
  /// Accepts the key used to generate the MAC, the message, and the MAC to be verified.
  /// Use this to prevent timing attacks during MAC verification.
  static bool verifyMac(List<int> m1, List<int> m2) {
    if (m1.length != m2.length) return false;
    int result = 0;
    for (int i = 0; i < m1.length; i++) {
      result |= (m1[i] ^ m2[i]);
    }
    return result == 0;
  }

  static Uint8List _buildMacData(Uint8List? aad, Uint8List bytes) {
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
}
