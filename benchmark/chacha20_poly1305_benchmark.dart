import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:chacha/export.dart';

import 'benchmark_utilities.dart';

class ChaCha20Poly1305Benchmark extends BenchmarkBase {
  const ChaCha20Poly1305Benchmark() : super('chacha20-poly1305');

  static void main() => ChaCha20Poly1305Benchmark().report();

  @override
  void run() => ChaCha20Poly1305(null, key, nonce, true).convert(bytes);
}

void main() => ChaCha20Poly1305Benchmark.main();
