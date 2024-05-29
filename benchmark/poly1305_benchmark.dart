part of 'benchmark.dart';

class Poly1305Benchmark extends BenchmarkBase {
  const Poly1305Benchmark() : super('poly1305', emitter: emitter);

  static void main() => Poly1305Benchmark().report();

  @override
  void run() => poly1305.convert(bytes);

  @override
  void exercise() {
    for (int i = 0; i < numRuns; i++) {
      run();
    }
  }
}

final Poly1305 poly1305 = Poly1305(key);
