import 'chacha20_benchmark.dart' as chacha20_benchmark;
import 'chacha20_poly1305_benchmark.dart' as chacha20poly1305_benchmark;
import 'poly1305_benchmark.dart' as poly1305_benchmark;

void main() {
  chacha20_benchmark.main();
  chacha20poly1305_benchmark.main();
  poly1305_benchmark.main();
}
