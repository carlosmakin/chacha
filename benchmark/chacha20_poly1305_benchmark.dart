part of 'benchmark.dart';

class ChaCha20Poly1305Benchmark extends BenchmarkBase {
  const ChaCha20Poly1305Benchmark() : super('chacha20-poly1305', emitter: emitter);

  static void main() => ChaCha20Poly1305Benchmark().report();

  @override
  void run() => chachapoly.convert(bytes);

  @override
  void exercise() {
    for (int i = 0; i < numRuns; i++) {
      run();
    }
  }
}

final ChaCha20Poly1305 chachapoly = ChaCha20Poly1305(null, key, nonce, true);
