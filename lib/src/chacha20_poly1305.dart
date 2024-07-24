part of '../export.dart';

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
      aad ?? Uint8List(0),
      ChaCha20(key, nonce, 1),
      Poly1305(generateKey(key, nonce)),
      encrypt,
    );
  }

  final bool _encrypt;
  final Uint8List _aad;
  final ChaCha20 _chacha20;
  final Poly1305 _poly1305;

  @override
  Uint8List convert(List<int> input) {
    final int len = input.length;
    if (_encrypt && len < 16) throw Exception('Invalid data length.');
    final Uint8List buffer = Uint8List(_encrypt ? len + 16 : len - 16);

    final Uint8List cipher = _encrypt
        ? Uint8List.sublistView(buffer..setAll(0, _chacha20.convert(input)), 0, len)
        : Uint8List.sublistView(buffer..setRange(0, len - 16, input), 0, len - 16);

    final int aadPaddedLen = (_aad.length + 15) & ~15;
    final int cipherPaddedLen = (cipher.length + 15) & ~15;

    _poly1305
      .._process(Uint8List(aadPaddedLen)..setAll(0, _aad))
      .._process(Uint8List(cipherPaddedLen)..setAll(0, cipher))
      .._process(Uint8List(16)
        ..buffer.asByteData(0).setUint64(0, _aad.length, Endian.little)
        ..buffer.asByteData(0).setUint64(8, cipher.length, Endian.little));

    final Uint8List mac = _poly1305._finalize();
    if (_encrypt) return buffer..setAll(len, mac);

    final List<int> tag = input.sublist(len - 16);
    if (!verifyMac(mac, tag)) throw Exception('MAC verification failed.');
    return _chacha20.convert(buffer);
  }

  /// Generates a Poly1305 key using the ChaCha20 block function with a zero counter as per RFC 8439.
  ///
  /// Accepts a 256-bit key and a 96-bit nonce.
  static Uint8List generateKey(Uint8List key, Uint8List nonce) {
    return ChaCha20(key, nonce, 0).chacha20Block().sublist(0, 32);
  }

  /// Verifies the integrity and authenticity of a message using its Poly1305 MAC.
  ///
  /// Accepts the key used to generate the MAC, the message, and the MAC to be verified.
  /// Use this to prevent timing attacks during MAC verification.
  static bool verifyMac(List<int> m1, List<int> m2) {
    if (m1.length != m2.length) return false;
    int result = 0;
    for (int i = 0; i < m1.length; ++i) {
      result |= (m1[i] ^ m2[i]);
    }
    return result == 0;
  }
}
