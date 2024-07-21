part of '../export.dart';

// Bit masks
const int mask32 = 0xFFFFFFFF;
const int mask26 = 0x03FFFFFF;

// Rotates the left bits of a 32-bit unsigned integer.
int rotateLeft32By16(int value) => (mask32 & (value << 16)) | (value >> 16);
int rotateLeft32By12(int value) => (mask32 & (value << 12)) | (value >> 20);
int rotateLeft32By08(int value) => (mask32 & (value << 08)) | (value >> 24);
int rotateLeft32By07(int value) => (mask32 & (value << 07)) | (value >> 25);

/// Ensures that the elements of the given `Uint32List` are in little-endian format.
/// If the host system is big-endian, this function flips the endianness of each element.
void ensureLittleEndian(Uint32List list) {
  if (Endian.host == Endian.little) return;
  final ByteData byteData = list.buffer.asByteData();
  for (int i = 0; i < list.length; i++) {
    list[i] = byteData.getUint32(i * 4, Endian.little);
  }
}
