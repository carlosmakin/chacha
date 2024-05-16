import 'dart:convert';
import 'dart:typed_data';

// ChaCha20 Stream Cipher (RFC 8439).
///
/// A symmetric key cipher offering high performance with 256-bit keys and a 96-bit nonce. ChaCha20
/// provides fast, secure encryption and decryption operations, featuring optional counter-based operation
/// for varied cryptographic uses, particularly effective in streaming data encryption.
class ChaCha20 extends Converter<List<int>, List<int>> {
  const ChaCha20._(this._counter, this._state);

  /// Converts data using ChaCha20 as per RFC 8439.
  ///
  /// Accepts a 256-bit key, a 96-bit nonce, and an optional counter (default: 1).
  factory ChaCha20(Uint8List key, Uint8List nonce, [int counter = 1]) {
    if (key.length != 32) throw ArgumentError('Invalid key');
    if (nonce.length != 12) throw ArgumentError('Invalid nonce');

    return ChaCha20._(
      counter,
      initState(
        key.buffer.asUint32List(),
        nonce.buffer.asUint32List(),
      ),
    );
  }

  final int _counter;
  final Uint32List _state;

  @override
  Uint8List convert(List<int> input, {int? counter}) {
    counter ??= _counter;

    final int inputSize = input.length;
    final Uint8List output = Uint8List(inputSize);

    final Uint8List keystream = Uint8List(64);
    final Uint32List workingState = Uint32List(16);

    // Process all full 64-byte blocks
    final int fullBlocks = inputSize ~/ 64;
    for (int j = 0; j < fullBlocks; j++) {
      chacha20Block(counter + j, keystream, _state, workingState);
      for (int i = 0; i < 64; i++) {
        output[j * 64 + i] = input[j * 64 + i] ^ keystream[i];
      }
    }

    // Handle any remaining partial block
    final int remaining = inputSize % 64;
    if (remaining != 0) {
      chacha20Block(counter + fullBlocks, keystream, _state, workingState);
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

// Initializes the state with the constants, key, and nonce
Uint32List initState(Uint32List key, Uint32List nonce) {
  final Uint32List state = Uint32List(16);

  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  state[4] = key[0];
  state[5] = key[1];
  state[6] = key[2];
  state[7] = key[3];
  state[8] = key[4];
  state[9] = key[5];
  state[10] = key[6];
  state[11] = key[7];
  state[13] = nonce[0];
  state[14] = nonce[1];
  state[15] = nonce[2];

  return state;
}

/// The ChaCha20 block function is the core of the ChaCha20 algorithm.
/// The function transforms a ChaCha state by running multiple quarter rounds.
void chacha20Block(int counter, Uint8List keystream, Uint32List state, Uint32List workingState) {
  state[12] = counter;
  _ensureLittleEndian(state);
  workingState.setRange(0, 16, state);
  _chacha20BlockRounds(workingState, state);
  keystream.setRange(0, 64, workingState.buffer.asUint8List());
}

/// Ensures that the elements of the given `Uint32List` are in little-endian format.
/// If the host system is big-endian, this function flips the endianness of each element.
void _ensureLittleEndian(Uint32List list) {
  if (Endian.host == Endian.little) return;

  final ByteData byteData = ByteData.view(list.buffer, list.offsetInBytes, list.lengthInBytes);
  for (int i = 0; i < list.length; i++) {
    list[i] = byteData.getUint32(i * 4, Endian.little);
  }
}

/// Performs the core rounds of the ChaCha20 block cipher.
///
/// The ChaCha20 algorithm operates by performing a series of rounds, each
/// consisting of "quarter-round" transformations. This function performs
/// these transformations directly on the state, modifying it in place.
///
/// The state undergoes 20 rounds in total, comprising 10 cycles of
/// "column rounds" followed by "diagonal rounds." Each round updates the state
/// using modular addition, bitwise XOR, and left rotation operations.
void _chacha20BlockRounds(Uint32List ws, Uint32List s) {
  int s0 = ws[0];
  int s1 = ws[1];
  int s2 = ws[2];
  int s3 = ws[3];
  int s4 = ws[4];
  int s5 = ws[5];
  int s6 = ws[6];
  int s7 = ws[7];
  int s8 = ws[8];
  int s9 = ws[9];
  int s10 = ws[10];
  int s11 = ws[11];
  int s12 = ws[12];
  int s13 = ws[13];
  int s14 = ws[14];
  int s15 = ws[15];

  for (int i = 0; i < 10; i++) {
    // Column rounds

    // Quarter round on (0, 4, 8, 12)
    s0 = 0xFFFFFFFF & (s0 + s4);
    s12 = _rotateLeft32By16(s12 ^ s0);
    s8 = 0xFFFFFFFF & (s8 + s12);
    s4 = _rotateLeft32By12(s4 ^ s8);
    s0 = 0xFFFFFFFF & (s0 + s4);
    s12 = _rotateLeft32By8(s12 ^ s0);
    s8 = 0xFFFFFFFF & (s8 + s12);
    s4 = _rotateLeft32By7(s4 ^ s8);

    // Quarter round on (1, 5, 9, 13)
    s1 = 0xFFFFFFFF & (s1 + s5);
    s13 = _rotateLeft32By16(s13 ^ s1);
    s9 = 0xFFFFFFFF & (s9 + s13);
    s5 = _rotateLeft32By12(s5 ^ s9);
    s1 = 0xFFFFFFFF & (s1 + s5);
    s13 = _rotateLeft32By8(s13 ^ s1);
    s9 = 0xFFFFFFFF & (s9 + s13);
    s5 = _rotateLeft32By7(s5 ^ s9);

    // Quarter round on (2, 6, 10, 14)
    s2 = 0xFFFFFFFF & (s2 + s6);
    s14 = _rotateLeft32By16(s14 ^ s2);
    s10 = 0xFFFFFFFF & (s10 + s14);
    s6 = _rotateLeft32By12(s6 ^ s10);
    s2 = 0xFFFFFFFF & (s2 + s6);
    s14 = _rotateLeft32By8(s14 ^ s2);
    s10 = 0xFFFFFFFF & (s10 + s14);
    s6 = _rotateLeft32By7(s6 ^ s10);

    // Quarter round on (3, 7, 11, 15)
    s3 = 0xFFFFFFFF & (s3 + s7);
    s15 = _rotateLeft32By16(s15 ^ s3);
    s11 = 0xFFFFFFFF & (s11 + s15);
    s7 = _rotateLeft32By12(s7 ^ s11);
    s3 = 0xFFFFFFFF & (s3 + s7);
    s15 = _rotateLeft32By8(s15 ^ s3);
    s11 = 0xFFFFFFFF & (s11 + s15);
    s7 = _rotateLeft32By7(s7 ^ s11);

    // Diagonal rounds

    // Quarter round on (0, 5, 10, 15)
    s0 = 0xFFFFFFFF & (s0 + s5);
    s15 = _rotateLeft32By16(s15 ^ s0);
    s10 = 0xFFFFFFFF & (s10 + s15);
    s5 = _rotateLeft32By12(s5 ^ s10);
    s0 = 0xFFFFFFFF & (s0 + s5);
    s15 = _rotateLeft32By8(s15 ^ s0);
    s10 = 0xFFFFFFFF & (s10 + s15);
    s5 = _rotateLeft32By7(s5 ^ s10);

    // Quarter round on (1, 6, 11, 12)
    s1 = 0xFFFFFFFF & (s1 + s6);
    s12 = _rotateLeft32By16(s12 ^ s1);
    s11 = 0xFFFFFFFF & (s11 + s12);
    s6 = _rotateLeft32By12(s6 ^ s11);
    s1 = 0xFFFFFFFF & (s1 + s6);
    s12 = _rotateLeft32By8(s12 ^ s1);
    s11 = 0xFFFFFFFF & (s11 + s12);
    s6 = _rotateLeft32By7(s6 ^ s11);

    // Quarter round on (2, 7, 8, 13)
    s2 = 0xFFFFFFFF & (s2 + s7);
    s13 = _rotateLeft32By16(s13 ^ s2);
    s8 = 0xFFFFFFFF & (s8 + s13);
    s7 = _rotateLeft32By12(s7 ^ s8);
    s2 = 0xFFFFFFFF & (s2 + s7);
    s13 = _rotateLeft32By8(s13 ^ s2);
    s8 = 0xFFFFFFFF & (s8 + s13);
    s7 = _rotateLeft32By7(s7 ^ s8);

    // Quarter round on (3, 4, 9, 14)
    s3 = 0xFFFFFFFF & (s3 + s4);
    s14 = _rotateLeft32By16(s14 ^ s3);
    s9 = 0xFFFFFFFF & (s9 + s14);
    s4 = _rotateLeft32By12(s4 ^ s9);
    s3 = 0xFFFFFFFF & (s3 + s4);
    s14 = _rotateLeft32By8(s14 ^ s3);
    s9 = 0xFFFFFFFF & (s9 + s14);
    s4 = _rotateLeft32By7(s4 ^ s9);
  }

  // Save local variables back to state
  ws[0] = s0 += s[0];
  ws[1] = s1 += s[1];
  ws[2] = s2 += s[2];
  ws[3] = s3 += s[3];
  ws[4] = s4 += s[4];
  ws[5] = s5 += s[5];
  ws[6] = s6 += s[6];
  ws[7] = s7 += s[7];
  ws[8] = s8 += s[8];
  ws[9] = s9 += s[9];
  ws[10] = s10 += s[10];
  ws[11] = s11 += s[11];
  ws[12] = s12 += s[12];
  ws[13] = s13 += s[13];
  ws[14] = s14 += s[14];
  ws[15] = s15 += s[15];
}

/// Rotates the left bits of a 32-bit unsigned integer.
int _rotateLeft32By16(int value) => (0xFFFFFFFF & (value << 16)) | (value >> 16);
int _rotateLeft32By12(int value) => (0xFFFFFFFF & (value << 12)) | (value >> 20);
int _rotateLeft32By8(int value) => (0xFFFFFFFF & (value << 8)) | (value >> 24);
int _rotateLeft32By7(int value) => (0xFFFFFFFF & (value << 7)) | (value >> 25);
