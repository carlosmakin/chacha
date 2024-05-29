part of 'benchmark.dart';

class ChaCha20Benchmark extends BenchmarkBase {
  const ChaCha20Benchmark() : super('chacha20', emitter: emitter);

  static void main() => ChaCha20Benchmark().report();

  @override
  void run() => chacha20.convert(bytes);

  @override
  void exercise() {
    for (int i = 0; i < numRuns; i++) {
      run();
    }
  }
}

final ChaCha20 chacha20 = ChaCha20(key, nonce);
