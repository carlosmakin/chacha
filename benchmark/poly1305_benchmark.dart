import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:chacha/export.dart';

import 'utilities.dart';

class Poly1305Benchmark extends BenchmarkBase {
  const Poly1305Benchmark() : super('poly1305');

  static void main() => Poly1305Benchmark().report();

  @override
  void run() => poly1305.convert(bytes);
}

void main() => Poly1305Benchmark.main();

final Poly1305 poly1305 = Poly1305(key);
