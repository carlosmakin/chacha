## ChaCha 💃

### Overview

This repository hosts an implementation of the ChaCha20 stream cipher, Poly1305 message authentication code, and ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) construction as per [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439). These cryptographic algorithms offer robust solutions for ensuring data confidentiality, integrity, and authenticity.

### ChaCha20

ChaCha20 is a modern stream cipher known for its speed and security. It is designed to provide strong encryption and has become a popular choice in various cryptographic protocols, such as TLS and secure messaging applications.

#### Key Features:
- **High Speed**: Excels in software implementations, especially on platforms without specialized hardware support for cryptography.
- **Security**: Designed to be secure against a wide range of cryptographic attacks.
- **Flexibility**: Easily adaptable for both large data encryption and real-time data streaming.

#### Best Practices:
- Ensure unique nonces for each encryption operation.
- Securely manage and store encryption keys.

### Poly1305

Poly1305 is a fast and secure message authentication code (MAC) that works in conjunction with a cipher like ChaCha20. It provides a strong level of assurance against message tampering.

#### Key Features:
- **Efficiency**: Exceptionally fast, making it suitable for high-throughput applications.
- **Security**: Offers strong guarantees of authenticity.
- **One-Time Key Usage**: Each key must only be used once to maintain security.

#### Best Practices:
- Never reuse a key; always generate a new key for each message.
- Combine with a secure cipher like ChaCha20 for complete data protection.

### ChaCha20-Poly1305 AEAD

ChaCha20-Poly1305 AEAD combines the strengths of ChaCha20 and Poly1305, encrypting and authenticating data in a single step. It's recommended for scenarios where both confidentiality and integrity are crucial.

#### Key Features:
- **Authenticated Encryption**: Simultaneously encrypts and authenticates data.
- **Nonce-Misuse Resistance**: Provides security even if nonces are reused (though nonce reuse is not recommended).
- **Efficient**: Leverages the performance benefits of ChaCha20 and Poly1305.

#### Best Practices:
- Avoid nonce reuse to ensure the highest level of security.
- Verify the authenticity of decrypted data before using it.

## Background and History

### ChaCha20

Developed by Daniel J. Bernstein, ChaCha20 is an evolution of the earlier Salsa20 cipher. It was designed to provide strong cryptographic security while being highly efficient in software implementations.

### Poly1305

Also developed by Daniel J. Bernstein, Poly1305 provides a way to authenticate messages securely and is often used in combination with ciphers like ChaCha20.

### RFC 8439

RFC 8439 standardizes the algorithms and provides comprehensive guidelines for their implementation and use, ensuring consistency and security across different applications.

## Usage Examples

### Real-World Use Case: Secure File Encryption

**Scenario**: Encrypting a sensitive document using ChaCha20.

```dart
import 'dart:typed_data';
import 'package:your_package/chacha20.dart';

void encryptFile(Uint8List fileData, Uint8List key, Uint8List nonce) {
  Uint8List encryptedData = ChaCha20.encrypt(key, nonce, fileData);
  // Save or transmit encryptedData
}
```

### Real-World Use Case: Data Authentication

**Scenario**: Generating a MAC for a message using Poly1305.

```dart
import 'dart:typed_data';
import 'package:your_package/poly1305.dart';

Uint8List authenticateMessage(Uint8List message, Uint8List key) {
  Uint8List tag = Poly1305.computeMac(message, key);
  // Use the tag for message verification
}
```

### Real-World Use Case: Secure Communication

**Scenario**: Encrypting and authenticating a message using ChaCha20-Poly1305 AEAD.

```dart
import 'dart:typed_data';
import 'package:your_package/chacha20_poly1305.dart';

Uint8List secureCommunication(Uint8List message, Uint8List key, Uint8List nonce) {
  Uint8List encryptedMessage = ChaCha20Poly1305.encrypt(key, nonce, message);
  // Send encryptedMessage securely
}
```

## Contribution

Contributions to improve the implementation, enhance security, and extend functionality are welcome. If you find any issues or have suggestions, please feel free to open an issue or submit a pull request.
