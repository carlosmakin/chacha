import 'dart:typed_data';

/// Ensures that the elements of the given `Uint32List` are in little-endian format.
/// If the host system is big-endian, this function flips the endianness of each element.
void _ensureLittleEndian(Uint32List list) {
  if (Endian.host == Endian.little) return;

  final ByteData byteData = ByteData.view(list.buffer, list.offsetInBytes, list.lengthInBytes);
  for (int i = 0; i < list.length; i++) {
    list[i] = byteData.getUint32(i * 4, Endian.little);
  }
}

/// Rotates the left bits of a 32-bit unsigned integer.
int _rotateLeft32By16(int value) => (0xFFFFFFFF & (value << 16)) | (value >> 16);
int _rotateLeft32By12(int value) => (0xFFFFFFFF & (value << 12)) | (value >> 20);
int _rotateLeft32By8(int value) => (0xFFFFFFFF & (value << 8)) | (value >> 24);
int _rotateLeft32By7(int value) => (0xFFFFFFFF & (value << 7)) | (value >> 25);

/// Performs the core rounds of the ChaCha20 block cipher.
///
/// The ChaCha20 algorithm operates by performing a series of rounds, each
/// consisting of "quarter-round" transformations. This function performs
/// these transformations directly on the state, modifying it in place.
///
/// The state undergoes 20 rounds in total, comprising 10 cycles of
/// "column rounds" followed by "diagonal rounds." Each round updates the state
/// using modular addition, bitwise XOR, and left rotation operations.
void _chacha20BlockRounds(Uint32List state) {
  int s0 = state[0];
  int s1 = state[1];
  int s2 = state[2];
  int s3 = state[3];
  int s4 = state[4];
  int s5 = state[5];
  int s6 = state[6];
  int s7 = state[7];
  int s8 = state[8];
  int s9 = state[9];
  int s10 = state[10];
  int s11 = state[11];
  int s12 = state[12];
  int s13 = state[13];
  int s14 = state[14];
  int s15 = state[15];

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
  state[0] = s0;
  state[1] = s1;
  state[2] = s2;
  state[3] = s3;
  state[4] = s4;
  state[5] = s5;
  state[6] = s6;
  state[7] = s7;
  state[8] = s8;
  state[9] = s9;
  state[10] = s10;
  state[11] = s11;
  state[12] = s12;
  state[13] = s13;
  state[14] = s14;
  state[15] = s15;
}

/// The ChaCha20 block function is the core of the ChaCha20 algorithm.
/// The function transforms a ChaCha state by running multiple quarter rounds.
///
/// The inputs to ChaCha20 are:
///
/// - A 256-bit key, treated as a concatenation of eight 32-bit little-endian integers.
/// - A 96-bit nonce, treated as a concatenation of three 32-bit little-endian integers
/// - A 32-bit block count parameter, treated as a 32-bit little-endian integer.
///
///The output is 64 random-looking bytes.
Uint8List chacha20Block(Uint32List key, Uint32List nonce, int counter) {
  // Initialize the state with the constants, key, counter, and nonce
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
  state[12] = counter;
  state[13] = nonce[0];
  state[14] = nonce[1];
  state[15] = nonce[2];

  // Flip endianness only if the system is big-endian
  _ensureLittleEndian(state);

  // Initialize working state
  final Uint32List workingState = Uint32List.fromList(state);

  // Perform block function
  _chacha20BlockRounds(workingState);

  // Add the original state to the working state
  for (int i = 0; i < 16; i++) {
    workingState[i] += state[i];
  }

  return workingState.buffer.asUint8List();
}

/// Encrypts or decrypts data using ChaCha20 algorithm, configurable for both encryption and decryption.
/// Accepts a 256-bit key, a 96-bit nonce, data, and an optional counter (default is 1).
Uint8List chacha20(Uint8List key, Uint8List nonce, Uint8List data, [int counter = 1]) {
  if (key.length != 32) throw ArgumentError('Invalid key');
  if (nonce.length != 12) throw ArgumentError('Invalid nonce');
  if (data.length >= 274877906880) throw ArgumentError('Maximum size reached');

  final int dataSize = data.lengthInBytes;
  final Uint8List output = Uint8List(dataSize);

  final Uint32List key32Bit = Uint32List.view(key.buffer);
  final Uint32List nonce32Bit = Uint32List.view(nonce.buffer);

  // Encrypt each full block
  final int fullBlocks = dataSize ~/ 64;
  for (int j = 0; j < fullBlocks; j++) {
    final Uint8List keyStream = chacha20Block(key32Bit, nonce32Bit, counter + j);
    for (int i = 0; i < 64; i++) {
      output[j * 64 + i] = data[j * 64 + i] ^ keyStream[i];
    }
  }

  // Handle any remaining partial block
  final int remaining = dataSize % 64;
  if (remaining != 0) {
    final Uint8List keyStream = chacha20Block(key32Bit, nonce32Bit, counter + fullBlocks);
    final int start = fullBlocks * 64;
    for (int i = 0; i < remaining; i++) {
      output[start + i] = data[start + i] ^ keyStream[i];
    }
  }

  return output;
}
