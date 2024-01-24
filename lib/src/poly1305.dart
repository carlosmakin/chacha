import 'dart:typed_data';

/// Converts a list of bytes in little-endian order to a BigInt.
/// In little-endian, the least significant byte is at the lowest index.
BigInt _leBytesToBigInt(Uint8List bytes) {
  // Initialize 'aggregator' to accumulate the first 7 bytes efficiently.
  // This 64-bit int is used for its efficiency before transitioning to BigInt.
  int aggregator = 0;

  // Accumulate each byte into 'aggregator', shifting according to byte position.
  // This respects little-endian order, placing the least significant byte first.
  aggregator |= bytes[0];
  aggregator |= bytes[1] << 8;
  aggregator |= bytes[2] << 16;
  aggregator |= bytes[3] << 24;
  aggregator |= bytes[4] << 32;
  aggregator |= bytes[5] << 40;
  aggregator |= bytes[6] << 48;

  // Convert 'aggregator' to BigInt for handling larger numbers.
  // Necessary for values exceeding the capacity of a 64-bit int.
  BigInt result = BigInt.from(aggregator);

  // Process remaining bytes (if any) beyond the first 7 as BigInts.
  // Continue shifting and combining into 'result' for the correct total value.
  for (int i = 7; i < bytes.length; i++) {
    result |= BigInt.from(bytes[i]) << (8 * i);
  }

  return result;
}

// Convert a BigInt to a list of 16 bytes in little-endian order.
Uint8List _bigIntTo16LeBytes(BigInt num) {
  final Uint8List bytes = Uint8List(16);
  final BigInt mask = BigInt.from(0xff);
  for (int i = 0; i < 16; i++) {
    bytes[i] = (num >> (8 * i) & mask).toInt();
  }
  return bytes;
}

// Clamp function as specified in RFC 8439.
void _clamp(Uint8List r) {
  r[3] &= 15;
  r[7] &= 15;
  r[11] &= 15;
  r[15] &= 15;
  r[4] &= 252;
  r[8] &= 252;
  r[12] &= 252;
}

/// Poly1305 MAC function algorithm as specified in RFC 8439.
Uint8List poly1305Mac(Uint8List msg, Uint8List key) {
  if (key.length < 16) throw ArgumentError('Invalid key');

  final Uint8List rBytes = key.sublist(0, 16);
  _clamp(rBytes);

  final BigInt r = _leBytesToBigInt(rBytes);
  final BigInt s = _leBytesToBigInt(key.sublist(16, 32));

  BigInt accumulator = BigInt.zero;
  final BigInt p = (BigInt.one << 130) - BigInt.from(5); // 2^130 - 5

  // Preallocate buffer for performance
  final Uint8List block = Uint8List(17);
  block[16] = 1; // Add one bit beyond the number of bytes for all full blocks

  // Process all full 16-byte blocks
  final int fullBlockEnd = msg.length - (msg.length % 16);
  for (int i = 0; i < fullBlockEnd; i += 16) {
    for (int j = 0; j < 16; j++) {
      block[j] = msg[i + j];
    }
    final BigInt n = _leBytesToBigInt(block);
    accumulator = (accumulator + n) * r % p;
  }

  // Process the final block, if there is any remainder
  if (fullBlockEnd < msg.length) {
    final int finalBlockLen = msg.length - fullBlockEnd;
    for (int j = 0; j < finalBlockLen; j++) {
      block[j] = msg[fullBlockEnd + j];
    }
    block[finalBlockLen] = 1;
    for (int j = finalBlockLen + 1; j < 17; j++) {
      block[j] = 0;
    }
    final BigInt n = _leBytesToBigInt(block);
    accumulator = (accumulator + n) * r % p;
  }

  // Zero out the block for security
  for (int j = 0; j < 17; j++) {
    block[j] = 0;
  }

  accumulator = (accumulator + s) % p;
  return _bigIntTo16LeBytes(accumulator);
}
