import 'dart:typed_data';

final Uint8List bytes = Uint8List.fromList(
  <int>[for (int i = 0; i < 1000000; i++) i & 0xFF],
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
