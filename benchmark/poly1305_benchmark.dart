import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:chacha/export.dart';

class ChaCha20Benchmark extends BenchmarkBase {
  const ChaCha20Benchmark() : super('chacha20');

  static void main() => ChaCha20Benchmark().report();

  @override
  void run() => poly1305.convert(bytes);
}

void main() => ChaCha20Benchmark.main();

final Uint8List bytes = Uint8List.fromList(
  <int>[for (int i = 0; i < 1000000; i++) i & 0xFF],
);

final Poly1305 poly1305 = Poly1305(key);

final Uint8List key = Uint8List.fromList(<int>[
  00, 01, 02, 03, 04, 05, 06, 07, //
  08, 09, 10, 11, 12, 13, 14, 15, //
  16, 17, 18, 19, 20, 21, 22, 23, //
  24, 25, 26, 27, 28, 29, 30, 31, //
]);
