part of '../export.dart';

/// ChaCha20 Stream Cipher (RFC 8439).
///
/// A symmetric key cipher offering high performance with 256-bit keys and a 96-bit nonce. ChaCha20
/// provides fast, secure encryption and decryption operations, featuring optional counter-based operation
/// for varied cryptographic uses, particularly effective in streaming data encryption.
class ChaCha20 extends Converter<List<int>, List<int>> {
  const ChaCha20._(this._counter, this._state, this._workingState);

  /// Converts data using ChaCha20 as per RFC 8439.
  ///
  /// Accepts a 256-bit key, a 96-bit nonce, and an optional counter (default: 1).
  factory ChaCha20(Uint8List key, Uint8List nonce, [int counter = 1]) {
    if (key.length != 32) throw ArgumentError('Invalid key');
    if (nonce.length != 12) throw ArgumentError('Invalid nonce');

    // Initializes the state with the constants, key, and nonce
    final Uint32List state = Uint32List(16);
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    state.setAll(04, key.buffer.asInt32List());
    state.setAll(13, nonce.buffer.asInt32List());

    return ChaCha20._(counter, state, Uint32List(16));
  }

  final int _counter;
  final Uint32List _state;
  final Uint32List _workingState;

  @override
  Uint8List convert(List<int> input, {int? counter}) {
    counter ??= _counter;

    final int inputSize = input.length;
    final Uint8List output = Uint8List(inputSize);

    final Uint8List keystream = Uint8List(64);

    // Process all full 64-byte blocks
    final int fullBlocks = inputSize ~/ 64;
    for (int j = 0; j < fullBlocks; j++) {
      chacha20Block(counter + j, keystream);
      for (int i = 0; i < 64; i++) {
        output[j * 64 + i] = input[j * 64 + i] ^ keystream[i];
      }
    }

    // Handle any remaining partial block
    final int remaining = inputSize % 64;
    if (remaining != 0) {
      chacha20Block(counter + fullBlocks, keystream);
      final int start = fullBlocks * 64;
      for (int i = 0; i < remaining; i++) {
        output[start + i] = input[start + i] ^ keystream[i];
      }
    }

    return output;
  }

  @override
  Sink<Uint8List> startChunkedConversion(Sink<List<int>> sink) {
    return _ChaCha20Sink(this, sink);
  }

  /// The ChaCha20 block function is the core of the ChaCha20 algorithm.
  void chacha20Block(int counter, Uint8List keystream) {
    _state[12] = counter;
    ensureLittleEndian(_state);
    _workingState.setRange(0, 16, _state);
    _chacha20BlockRounds(_state, _workingState);
    keystream.setRange(0, 64, _workingState.buffer.asUint8List());
  }

  /// Performs the core rounds of the ChaCha20 block cipher.
  void _chacha20BlockRounds(Uint32List s, Uint32List ws) {
    int s00 = ws[00], s01 = ws[01], s02 = ws[02], s03 = ws[03];
    int s04 = ws[04], s05 = ws[05], s06 = ws[06], s07 = ws[07];
    int s08 = ws[08], s09 = ws[09], s10 = ws[10], s11 = ws[11];
    int s12 = ws[12], s13 = ws[13], s14 = ws[14], s15 = ws[15];

    for (int i = 0; i < 10; i++) {
      // Column rounds

      // Quarter round on (0, 4, 8, 12)
      s00 = mask32 & (s00 + s04);
      s12 = rotateLeft32By16(s12 ^ s00);
      s08 = mask32 & (s08 + s12);
      s04 = rotateLeft32By12(s04 ^ s08);
      s00 = mask32 & (s00 + s04);
      s12 = rotateLeft32By8(s12 ^ s00);
      s08 = mask32 & (s08 + s12);
      s04 = rotateLeft32By7(s04 ^ s08);

      // Quarter round on (1, 5, 9, 13)
      s01 = mask32 & (s01 + s05);
      s13 = rotateLeft32By16(s13 ^ s01);
      s09 = mask32 & (s09 + s13);
      s05 = rotateLeft32By12(s05 ^ s09);
      s01 = mask32 & (s01 + s05);
      s13 = rotateLeft32By8(s13 ^ s01);
      s09 = mask32 & (s09 + s13);
      s05 = rotateLeft32By7(s05 ^ s09);

      // Quarter round on (2, 6, 10, 14)
      s02 = mask32 & (s02 + s06);
      s14 = rotateLeft32By16(s14 ^ s02);
      s10 = mask32 & (s10 + s14);
      s06 = rotateLeft32By12(s06 ^ s10);
      s02 = mask32 & (s02 + s06);
      s14 = rotateLeft32By8(s14 ^ s02);
      s10 = mask32 & (s10 + s14);
      s06 = rotateLeft32By7(s06 ^ s10);

      // Quarter round on (3, 7, 11, 15)
      s03 = mask32 & (s03 + s07);
      s15 = rotateLeft32By16(s15 ^ s03);
      s11 = mask32 & (s11 + s15);
      s07 = rotateLeft32By12(s07 ^ s11);
      s03 = mask32 & (s03 + s07);
      s15 = rotateLeft32By8(s15 ^ s03);
      s11 = mask32 & (s11 + s15);
      s07 = rotateLeft32By7(s07 ^ s11);

      // Diagonal rounds

      // Quarter round on (0, 5, 10, 15)
      s00 = mask32 & (s00 + s05);
      s15 = rotateLeft32By16(s15 ^ s00);
      s10 = mask32 & (s10 + s15);
      s05 = rotateLeft32By12(s05 ^ s10);
      s00 = mask32 & (s00 + s05);
      s15 = rotateLeft32By8(s15 ^ s00);
      s10 = mask32 & (s10 + s15);
      s05 = rotateLeft32By7(s05 ^ s10);

      // Quarter round on (1, 6, 11, 12)
      s01 = mask32 & (s01 + s06);
      s12 = rotateLeft32By16(s12 ^ s01);
      s11 = mask32 & (s11 + s12);
      s06 = rotateLeft32By12(s06 ^ s11);
      s01 = mask32 & (s01 + s06);
      s12 = rotateLeft32By8(s12 ^ s01);
      s11 = mask32 & (s11 + s12);
      s06 = rotateLeft32By7(s06 ^ s11);

      // Quarter round on (2, 7, 8, 13)
      s02 = mask32 & (s02 + s07);
      s13 = rotateLeft32By16(s13 ^ s02);
      s08 = mask32 & (s08 + s13);
      s07 = rotateLeft32By12(s07 ^ s08);
      s02 = mask32 & (s02 + s07);
      s13 = rotateLeft32By8(s13 ^ s02);
      s08 = mask32 & (s08 + s13);
      s07 = rotateLeft32By7(s07 ^ s08);

      // Quarter round on (3, 4, 9, 14)
      s03 = mask32 & (s03 + s04);
      s14 = rotateLeft32By16(s14 ^ s03);
      s09 = mask32 & (s09 + s14);
      s04 = rotateLeft32By12(s04 ^ s09);
      s03 = mask32 & (s03 + s04);
      s14 = rotateLeft32By8(s14 ^ s03);
      s09 = mask32 & (s09 + s14);
      s04 = rotateLeft32By7(s04 ^ s09);
    }

    // Save local variables back to working state
    ws[0] = s00 += s[0];
    ws[1] = s01 += s[1];
    ws[2] = s02 += s[2];
    ws[3] = s03 += s[3];
    ws[4] = s04 += s[4];
    ws[5] = s05 += s[5];
    ws[6] = s06 += s[6];
    ws[7] = s07 += s[7];
    ws[8] = s08 += s[8];
    ws[9] = s09 += s[9];
    ws[10] = s10 += s[10];
    ws[11] = s11 += s[11];
    ws[12] = s12 += s[12];
    ws[13] = s13 += s[13];
    ws[14] = s14 += s[14];
    ws[15] = s15 += s[15];
  }
}

class _ChaCha20Sink implements Sink<Uint8List> {
  _ChaCha20Sink(
    this._converter,
    this._outputSink,
  ) : _counter = _converter._counter;

  int _counter;

  final ChaCha20 _converter;
  final Sink<List<int>> _outputSink;

  @override
  void add(List<int> chunk) {
    _outputSink.add(_converter.convert(chunk, counter: _counter));
    _counter += (chunk.length / 64).ceil();
  }

  @override
  void close() => _outputSink.close();
}
