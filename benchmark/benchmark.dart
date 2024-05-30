import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:chacha/export.dart';

part 'chacha20_benchmark.dart';
part 'chacha20_poly1305_benchmark.dart';
part 'poly1305_benchmark.dart';

void main() {
  ChaCha20Poly1305Benchmark.main();
  ChaCha20Benchmark.main();
  Poly1305Benchmark.main();
}

const int numRuns = 10;
const int numBytes = 1024 * 1024; // 1MB
final Uint8List bytes = Uint8List.fromList(
  <int>[for (int i = 0; i < numBytes; i++) i & 0xFF],
);

final Uint8List key = Uint8List.fromList(<int>[
  00, 01, 02, 03, 04, 05, 06, 07, //
  08, 09, 10, 11, 12, 13, 14, 15, //
  16, 17, 18, 19, 20, 21, 22, 23, //
  24, 25, 26, 27, 28, 29, 30, 31, //
]);

final Uint8List nonce = Uint8List.fromList(<int>[
  00, 01, 02, 03, 04, 05, //
  08, 09, 10, 11, 12, 13, //
]);

const int oneMB = 1024 * 1024;

const BenchmarkEmitter emitter = BenchmarkEmitter();

class BenchmarkEmitter implements ScoreEmitter {
  const BenchmarkEmitter();

  @override
  void emit(String testName, double value) {
    final double microseconds = value / numRuns;
    final double seconds = microseconds / 1e6;
    final double throughput = (numBytes / oneMB) / seconds;
    print(
      'Benchmark Results for $testName:\n'
      '  Runs         : $numRuns x\n'
      '  Size         : $numBytes bytes\n'
      '  Runtime      : ${microseconds.toStringAsFixed(2)} us\n'
      '  Throughput   : ${throughput.toStringAsFixed(2)} MB/s\n',
    );
  }
}
