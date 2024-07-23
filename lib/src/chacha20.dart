part of '../export.dart';

/// ChaCha20 Stream Cipher (RFC 8439).
///
/// A symmetric key cipher offering high performance with 256-bit keys and a 96-bit nonce. ChaCha20
/// provides fast, secure encryption and decryption operations, featuring optional counter-based operation
/// for varied cryptographic uses, particularly effective in streaming data encryption.
class ChaCha20 extends Converter<List<int>, List<int>> {
  const ChaCha20._(this._state, this._keystream);

  /// Converts data using ChaCha20 as per RFC 8439.
  ///
  /// Accepts a 256-bit key, a 96-bit nonce, and an optional counter (default: 1).
  factory ChaCha20(Uint8List key, Uint8List nonce, [int counter = 1]) {
    if (key.length != 32) throw ArgumentError('Invalid key');
    if (nonce.length != 12) throw ArgumentError('Invalid nonce');

    // Initializes the state with the constants, key, and nonce.
    final Uint32List state = Uint32List(32);
    state[00] = 0x61707865;
    state[01] = 0x3320646e;
    state[02] = 0x79622d32;
    state[03] = 0x6b206574;
    state[12] = counter;
    state.setAll(04, key.buffer.asUint32List());
    state.setAll(13, nonce.buffer.asUint32List());
    ensureLittleEndian(state);

    return ChaCha20._(state, state.buffer.asUint8List(64));
  }

  final Uint32List _state;
  final Uint8List _keystream;

  @override
  Uint8List convert(List<int> input) {
    final Uint8List output = Uint8List.fromList(input);

    // Process all 64-byte chunks.
    final int block = input.length & ~63;
    for (int j = 0; j < block; j += 64, ++_state[12]) {
      _chacha20BlockRounds();
      output[j] ^= _keystream[00];
      output[j + 01] ^= _keystream[01];
      output[j + 02] ^= _keystream[02];
      output[j + 03] ^= _keystream[03];
      output[j + 04] ^= _keystream[04];
      output[j + 05] ^= _keystream[05];
      output[j + 06] ^= _keystream[06];
      output[j + 07] ^= _keystream[07];
      output[j + 08] ^= _keystream[08];
      output[j + 09] ^= _keystream[09];
      output[j + 10] ^= _keystream[10];
      output[j + 11] ^= _keystream[11];
      output[j + 12] ^= _keystream[12];
      output[j + 13] ^= _keystream[13];
      output[j + 14] ^= _keystream[14];
      output[j + 15] ^= _keystream[15];
      output[j + 16] ^= _keystream[16];
      output[j + 17] ^= _keystream[17];
      output[j + 18] ^= _keystream[18];
      output[j + 19] ^= _keystream[19];
      output[j + 20] ^= _keystream[20];
      output[j + 21] ^= _keystream[21];
      output[j + 22] ^= _keystream[22];
      output[j + 23] ^= _keystream[23];
      output[j + 24] ^= _keystream[24];
      output[j + 25] ^= _keystream[25];
      output[j + 26] ^= _keystream[26];
      output[j + 27] ^= _keystream[27];
      output[j + 28] ^= _keystream[28];
      output[j + 29] ^= _keystream[29];
      output[j + 30] ^= _keystream[30];
      output[j + 31] ^= _keystream[31];
      output[j + 32] ^= _keystream[32];
      output[j + 33] ^= _keystream[33];
      output[j + 34] ^= _keystream[34];
      output[j + 35] ^= _keystream[35];
      output[j + 36] ^= _keystream[36];
      output[j + 37] ^= _keystream[37];
      output[j + 38] ^= _keystream[38];
      output[j + 39] ^= _keystream[39];
      output[j + 40] ^= _keystream[40];
      output[j + 41] ^= _keystream[41];
      output[j + 42] ^= _keystream[42];
      output[j + 43] ^= _keystream[43];
      output[j + 44] ^= _keystream[44];
      output[j + 45] ^= _keystream[45];
      output[j + 46] ^= _keystream[46];
      output[j + 47] ^= _keystream[47];
      output[j + 48] ^= _keystream[48];
      output[j + 49] ^= _keystream[49];
      output[j + 50] ^= _keystream[50];
      output[j + 51] ^= _keystream[51];
      output[j + 52] ^= _keystream[52];
      output[j + 53] ^= _keystream[53];
      output[j + 54] ^= _keystream[54];
      output[j + 55] ^= _keystream[55];
      output[j + 56] ^= _keystream[56];
      output[j + 57] ^= _keystream[57];
      output[j + 58] ^= _keystream[58];
      output[j + 59] ^= _keystream[59];
      output[j + 60] ^= _keystream[60];
      output[j + 61] ^= _keystream[61];
      output[j + 62] ^= _keystream[62];
      output[j + 63] ^= _keystream[63];
    }

    // Process any remaining bytes.
    final int remaining = input.length % 64;
    if (remaining != 0) {
      _chacha20BlockRounds();
      for (int i = 0; i < remaining; ++i) {
        output[block + i] ^= _keystream[i];
      }
    }

    return output;
  }

  @override
  ByteConversionSink startChunkedConversion(Sink<List<int>> sink) {
    if (sink is! ByteConversionSink) sink = ByteConversionSink.from(sink);
    return _ChaCha20Sink(this, sink);
  }

  /// The ChaCha20 block function is the core of the ChaCha20 algorithm.
  Uint8List chacha20Block() {
    _chacha20BlockRounds();
    return Uint8List.fromList(_keystream);
  }

  /// Performs the core rounds of the ChaCha20 block cipher.
  void _chacha20BlockRounds() {
    int ws00 = _state[00], ws01 = _state[01], ws02 = _state[02], ws03 = _state[03];
    int ws04 = _state[04], ws05 = _state[05], ws06 = _state[06], ws07 = _state[07];
    int ws08 = _state[08], ws09 = _state[09], ws10 = _state[10], ws11 = _state[11];
    int ws12 = _state[12], ws13 = _state[13], ws14 = _state[14], ws15 = _state[15];

    for (int i = 0; i < 10; ++i) {
      // Column rounds

      // Quarter round on (0, 4, 8, 12)
      ws00 = mask32 & (ws00 + ws04);
      ws12 = rotateLeft32By16(ws12 ^ ws00);
      ws08 = mask32 & (ws08 + ws12);
      ws04 = rotateLeft32By12(ws04 ^ ws08);
      ws00 = mask32 & (ws00 + ws04);
      ws12 = rotateLeft32By08(ws12 ^ ws00);
      ws08 = mask32 & (ws08 + ws12);
      ws04 = rotateLeft32By07(ws04 ^ ws08);

      // Quarter round on (1, 5, 9, 13)
      ws01 = mask32 & (ws01 + ws05);
      ws13 = rotateLeft32By16(ws13 ^ ws01);
      ws09 = mask32 & (ws09 + ws13);
      ws05 = rotateLeft32By12(ws05 ^ ws09);
      ws01 = mask32 & (ws01 + ws05);
      ws13 = rotateLeft32By08(ws13 ^ ws01);
      ws09 = mask32 & (ws09 + ws13);
      ws05 = rotateLeft32By07(ws05 ^ ws09);

      // Quarter round on (2, 6, 10, 14)
      ws02 = mask32 & (ws02 + ws06);
      ws14 = rotateLeft32By16(ws14 ^ ws02);
      ws10 = mask32 & (ws10 + ws14);
      ws06 = rotateLeft32By12(ws06 ^ ws10);
      ws02 = mask32 & (ws02 + ws06);
      ws14 = rotateLeft32By08(ws14 ^ ws02);
      ws10 = mask32 & (ws10 + ws14);
      ws06 = rotateLeft32By07(ws06 ^ ws10);

      // Quarter round on (3, 7, 11, 15)
      ws03 = mask32 & (ws03 + ws07);
      ws15 = rotateLeft32By16(ws15 ^ ws03);
      ws11 = mask32 & (ws11 + ws15);
      ws07 = rotateLeft32By12(ws07 ^ ws11);
      ws03 = mask32 & (ws03 + ws07);
      ws15 = rotateLeft32By08(ws15 ^ ws03);
      ws11 = mask32 & (ws11 + ws15);
      ws07 = rotateLeft32By07(ws07 ^ ws11);

      // Diagonal rounds

      // Quarter round on (0, 5, 10, 15)
      ws00 = mask32 & (ws00 + ws05);
      ws15 = rotateLeft32By16(ws15 ^ ws00);
      ws10 = mask32 & (ws10 + ws15);
      ws05 = rotateLeft32By12(ws05 ^ ws10);
      ws00 = mask32 & (ws00 + ws05);
      ws15 = rotateLeft32By08(ws15 ^ ws00);
      ws10 = mask32 & (ws10 + ws15);
      ws05 = rotateLeft32By07(ws05 ^ ws10);

      // Quarter round on (1, 6, 11, 12)
      ws01 = mask32 & (ws01 + ws06);
      ws12 = rotateLeft32By16(ws12 ^ ws01);
      ws11 = mask32 & (ws11 + ws12);
      ws06 = rotateLeft32By12(ws06 ^ ws11);
      ws01 = mask32 & (ws01 + ws06);
      ws12 = rotateLeft32By08(ws12 ^ ws01);
      ws11 = mask32 & (ws11 + ws12);
      ws06 = rotateLeft32By07(ws06 ^ ws11);

      // Quarter round on (2, 7, 8, 13)
      ws02 = mask32 & (ws02 + ws07);
      ws13 = rotateLeft32By16(ws13 ^ ws02);
      ws08 = mask32 & (ws08 + ws13);
      ws07 = rotateLeft32By12(ws07 ^ ws08);
      ws02 = mask32 & (ws02 + ws07);
      ws13 = rotateLeft32By08(ws13 ^ ws02);
      ws08 = mask32 & (ws08 + ws13);
      ws07 = rotateLeft32By07(ws07 ^ ws08);

      // Quarter round on (3, 4, 9, 14)
      ws03 = mask32 & (ws03 + ws04);
      ws14 = rotateLeft32By16(ws14 ^ ws03);
      ws09 = mask32 & (ws09 + ws14);
      ws04 = rotateLeft32By12(ws04 ^ ws09);
      ws03 = mask32 & (ws03 + ws04);
      ws14 = rotateLeft32By08(ws14 ^ ws03);
      ws09 = mask32 & (ws09 + ws14);
      ws04 = rotateLeft32By07(ws04 ^ ws09);
    }

    // Save local variables back to working state.
    _state[16] = ws00 + _state[00];
    _state[17] = ws01 + _state[01];
    _state[18] = ws02 + _state[02];
    _state[19] = ws03 + _state[03];
    _state[20] = ws04 + _state[04];
    _state[21] = ws05 + _state[05];
    _state[22] = ws06 + _state[06];
    _state[23] = ws07 + _state[07];
    _state[24] = ws08 + _state[08];
    _state[25] = ws09 + _state[09];
    _state[26] = ws10 + _state[10];
    _state[27] = ws11 + _state[11];
    _state[28] = ws12 + _state[12];
    _state[29] = ws13 + _state[13];
    _state[30] = ws14 + _state[14];
    _state[31] = ws15 + _state[15];
  }
}

class _ChaCha20Sink implements ByteConversionSink {
  _ChaCha20Sink(this._converter, this._outputSink);

  final ChaCha20 _converter;
  final ByteConversionSink _outputSink;

  @override
  void add(List<int> chunk) => _outputSink.add(
        _converter.convert(chunk),
      );

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    add(chunk.sublist(start, end));
    if (isLast) close();
  }

  @override
  void close() => _outputSink.close();
}
