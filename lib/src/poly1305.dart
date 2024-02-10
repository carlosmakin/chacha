import 'dart:convert';
import 'dart:typed_data';

/// Poly1305 Message Authentication Code (MAC) (RFC 8439).
///
/// Implements a high-speed symmetric MAC algorithm using a 256-bit key. Poly1305 is designed to assure
/// message integrity and authenticity, effectively guarding against tampering in secure communication channels.
class Poly1305 extends Converter<List<int>, List<int>> {
  Poly1305._(this._block, this._r, this._s, this._p, this._accumulator);

  /// Generates a Poly1305 Message Authentication Code (MAC) as per RFC 8439.
  ///
  /// Accepts a 256-bit key for message integrity and authenticity.
  factory Poly1305(Uint8List key) {
    if (key.length != 32) throw ArgumentError('Invalid key');

    BigInt accumulator = BigInt.zero;
    final BigInt r = _leBytesToBigInt(_clamp(key.sublist(0, 16)));
    final BigInt s = _leBytesToBigInt(key.sublist(16, 32));
    final BigInt p = (BigInt.one << 130) - BigInt.from(5);
    final Uint8List block = Uint8List(17)..[16] = 1;

    return Poly1305._(block, r, s, p, accumulator);
  }

  BigInt _accumulator;

  final BigInt _r;
  final BigInt _s;
  final BigInt _p;
  final Uint8List _block;

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
      final BigInt n = _leBytesToBigInt(_block);
      _accumulator = (_accumulator + n) * _r % _p;
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
      final BigInt n = _leBytesToBigInt(_block);
      _accumulator = (_accumulator + n) * _r % _p;
    }
  }

  Uint8List _finalize() {
    _block.fillRange(0, 17, 0);
    _accumulator = (_accumulator + _s) % _p;
    return _bigIntTo16LeBytes(_accumulator);
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

/// Clamp function as specified in RFC 8439.
Uint8List _clamp(Uint8List r) {
  r[3] &= 15;
  r[7] &= 15;
  r[11] &= 15;
  r[15] &= 15;
  r[4] &= 252;
  r[8] &= 252;
  r[12] &= 252;

  return r;
}

/// Converts a list of bytes in little-endian order to a BigInt.
/// In little-endian, the least significant byte is at the lowest index.
BigInt _leBytesToBigInt(Uint8List bytes) {
  // Initialize variables for mixed approach
  int intLow = 0;
  int intMid = 0;
  int intHigh = 0;

  // Accumulate the first 7 bytes into 'intLow'
  intLow |= bytes[0];
  intLow |= bytes[1] << 8;
  intLow |= bytes[2] << 16;
  intLow |= bytes[3] << 24;
  intLow |= bytes[4] << 32;
  intLow |= bytes[5] << 40;
  intLow |= bytes[6] << 48;

  // Accumulate the next 7 bytes into 'intMid'
  intMid |= bytes[7];
  intMid |= bytes[8] << 8;
  intMid |= bytes[9] << 16;
  intMid |= bytes[10] << 24;
  intMid |= bytes[11] << 32;
  intMid |= bytes[12] << 40;
  intMid |= bytes[13] << 48;

  // Accumulate the last 3 bytes into 'intHigh'
  intHigh |= bytes[14];
  intHigh |= bytes[15] << 8;
  if (bytes.length == 17) intHigh |= bytes[16] << 16;

  // Initialize BigInts for final assembly
  BigInt bigIntLow = BigInt.from(intLow);
  BigInt bigIntMid = BigInt.from(intMid);
  BigInt bigIntHigh = BigInt.from(intHigh);

  // Shift up 'bigIntMid' and 'bigIntHigh' to make space
  bigIntLow |= (bigIntMid <<= 56);
  bigIntLow |= (bigIntHigh <<= 112);

  return bigIntLow;
}

/// Convert a BigInt to a list of 16 bytes in little-endian order.
Uint8List _bigIntTo16LeBytes(BigInt num) {
  final Uint8List bytes = Uint8List(16);
  final BigInt mask = BigInt.from(0xff);
  for (int i = 0; i < 16; i++) {
    bytes[i] = (num >> (8 * i) & mask).toInt();
  }
  return bytes;
}
