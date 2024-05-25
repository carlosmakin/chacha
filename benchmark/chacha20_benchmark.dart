import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:chacha/export.dart';

import 'benchmark_utilities.dart';

class ChaCha20Benchmark extends BenchmarkBase {
  const ChaCha20Benchmark() : super('chacha20');

  static void main() => ChaCha20Benchmark().report();

  @override
  void run() => chacha20.convert(bytes);
}

void main() => ChaCha20Benchmark.main();

final ChaCha20 chacha20 = ChaCha20(key, nonce);
