part of '../export.dart';

/// Poly1305 Message Authentication Code (MAC) (RFC 8439).
///
/// Implements a high-speed symmetric MAC algorithm using a 256-bit key. Poly1305 is designed to assure
/// message integrity and authenticity, effectively guarding against tampering in secure communication channels.
class Poly1305 extends Converter<List<int>, List<int>> {
  /// Generates a Poly1305 Message Authentication Code (MAC) as per RFC 8439.
  ///
  /// Accepts a 256-bit key for message integrity and authenticity.
  Poly1305(Uint8List key) {
    if (key.length != 32) throw ArgumentError('Invalid key');

    // Initialize r from the first 16 bytes of the key
    _r0 = key[0] | key[1] << 8 | key[2] << 16 | key[3] << 24;
    _r1 = key[3] >>> 2 | key[4] << 6 | key[5] << 14 | key[6] << 22;
    _r2 = key[6] >>> 4 | key[7] << 4 | key[8] << 12 | key[9] << 20;
    _r3 = key[9] >>> 6 | key[10] << 2 | key[11] << 10 | key[12] << 18;
    _r4 = key[13] | key[14] << 8 | key[15] << 16;

    // Clamp r according to RFC 8439 to prevent modular reduction weaknesses
    _r0 &= 0x03ffffff;
    _r1 &= 0x03ffff03;
    _r2 &= 0x03ffc0ff;
    _r3 &= 0x03f03fff;
    _r4 &= 0x000fffff;

    // Precompute 5*r values for optimization
    _g1 = 5 * _r1;
    _g2 = 5 * _r2;
    _g3 = 5 * _r3;
    _g4 = 5 * _r4;

    // Initialize s from the second 16 bytes of the key
    _s0 = key[16] | key[17] << 8 | key[18] << 16 | key[19] << 24;
    _s1 = key[20] | key[21] << 8 | key[22] << 16 | key[23] << 24;
    _s2 = key[24] | key[25] << 8 | key[26] << 16 | key[27] << 24;
    _s3 = key[28] | key[29] << 8 | key[30] << 16 | key[31] << 24;

    // Zero-initialize the accumulator
    _a0 = _a1 = _a2 = _a3 = _a4 = 0;
  }

  // Internal state variables for r, s, accumulator, and g
  int _r0 = 0, _r1 = 0, _r2 = 0, _r3 = 0, _r4 = 0;
  int _s0 = 0, _s1 = 0, _s2 = 0, _s3 = 0;
  int _a0 = 0, _a1 = 0, _a2 = 0, _a3 = 0, _a4 = 0;
  int _g1 = 0, _g2 = 0, _g3 = 0, _g4 = 0;

  // A 17-byte block initialized with 0s, the last byte is set to 1
  final Uint8List _block = Uint8List(17)..[16] = 1;

  @override
  Uint8List convert(List<int> input) {
    return (this.._process(input))._finalize();
  }

  void _process(List<int> input) {
    // Process all full 16-byte blocks
    final int dataSize = input.length;
    final int fullBlocks = dataSize ~/ 16;
    for (int j = 0; j < fullBlocks; j++) {
      for (int i = 0; i < 16; i++) {
        _block[i] = input[j * 16 + i];
      }
      _accumulate(_block);
    }

    // Handle any remaining partial block
    final int remaining = dataSize % 16;
    if (remaining != 0) {
      final int start = fullBlocks * 16;
      for (int j = 0; j < remaining; j++) {
        _block[j] = input[start + j];
      }
      _block[remaining] = 1;
      for (int j = remaining + 1; j < 17; j++) {
        _block[j] = 0;
      }
      _accumulate(_block);
    }
  }

  void _accumulate(Uint8List chunk) {
    // Temporary variables for modular reduction
    int d0, d1, d2, d3, d4;

    // Add block to the accumulator: a += n
    _a0 += chunk[0] | chunk[1] << 8 | chunk[2] << 16 | (chunk[3] & 0x03) << 24;
    _a1 += chunk[3] >>> 2 | chunk[4] << 6 | chunk[5] << 14 | (chunk[6] & 0xF) << 22;
    _a2 += chunk[6] >>> 4 | chunk[7] << 4 | chunk[8] << 12 | (chunk[9] & 0x3F) << 20;
    _a3 += chunk[9] >>> 6 | chunk[10] << 2 | chunk[11] << 10 | chunk[12] << 18;
    _a4 += chunk[13] | chunk[14] << 8 | chunk[15] << 16 | (chunk[16] & 0x03) << 24;

    // Multiply the accumulator by r: a *= r
    d0 = _a0 * _r0 + _a1 * _g4 + _a2 * _g3 + _a3 * _g2 + _a4 * _g1;
    d1 = _a0 * _r1 + _a1 * _r0 + _a2 * _g4 + _a3 * _g3 + _a4 * _g2;
    d2 = _a0 * _r2 + _a1 * _r1 + _a2 * _r0 + _a3 * _g4 + _a4 * _g3;
    d3 = _a0 * _r3 + _a1 * _r2 + _a2 * _r1 + _a3 * _r0 + _a4 * _g4;
    d4 = _a0 * _r4 + _a1 * _r3 + _a2 * _r2 + _a3 * _r1 + _a4 * _r0;

    // Reduce accumulator by modulo 2^130 - 5: a %= p
    d1 += d0 >>> 26;
    d2 += d1 >>> 26;
    d3 += d2 >>> 26;
    d4 += d3 >>> 26;
    _a0 = d0 & mask26;
    _a1 = d1 & mask26;
    _a2 = d2 & mask26;
    _a3 = d3 & mask26;
    _a4 = d4 & mask26;
    _a0 += 5 * (d4 >>> 26);
    _a1 += _a0 >>> 26;
    _a0 &= mask26;
  }

  Uint8List _finalize() {
    // Zero out block buffer
    _block.fillRange(0, 17, 0);

    // Temporary variables final computations
    int d0, d1, d2, d3, d4;

    // Carry propagation
    _a1 += _a0 >>> 26;
    _a2 += _a1 >>> 26;
    _a3 += _a2 >>> 26;
    _a4 += _a3 >>> 26;
    _a0 &= mask26;
    _a1 &= mask26;
    _a2 &= mask26;
    _a3 &= mask26;

    // Compute the difference of the accumulator and p: d = a - p
    d0 = _a0 + 5;
    d1 = _a1 + (d0 >>> 26);
    d2 = _a2 + (d1 >>> 26);
    d3 = _a3 + (d2 >>> 26);
    d4 = _a4 + (d3 >>> 26) - (1 << 26);
    d4 &= mask32;

    // Swap to d if a > prime mod (ensuring result stays within finite field bounds)
    if ((d4 >>> 31) != 1) {
      _a0 = d0 & mask26;
      _a1 = d1 & mask26;
      _a2 = d2 & mask26;
      _a3 = d3 & mask26;
      _a4 = d4 & mask26;
    }

    // Serialize the result into 32-bit units, taking into account 128-bit overflow
    _a0 = ((_a0) | (_a1 << 26)) & mask32;
    _a1 = ((_a1 >>> 6) | (_a2 << 20)) & mask32;
    _a2 = ((_a2 >>> 12) | (_a3 << 14)) & mask32;
    _a3 = ((_a3 >>> 18) | (_a4 << 8)) & mask32;

    // Add s to the accumulator for the final tag: a += s
    _a0 += _s0;
    _a1 += _s1 + (_a0 >>> 32);
    _a2 += _s2 + (_a1 >>> 32);
    _a3 += _s3 + (_a2 >>> 32);

    // Return the final MAC as a Uint8List
    return Uint32List.fromList(<int>[_a0, _a1, _a2, _a3]).buffer.asUint8List();
  }

  @override
  Sink<List<int>> startChunkedConversion(Sink<List<int>> sink) {
    return _Poly1305Sink(this, sink);
  }
}

class _Poly1305Sink implements Sink<List<int>> {
  const _Poly1305Sink(this._converter, this._outputSink);

  final Poly1305 _converter;
  final Sink<List<int>> _outputSink;

  @override
  void add(List<int> chunk) => _converter._process(chunk);

  @override
  void close() => _outputSink
    ..add(_converter._finalize())
    ..close();
}
