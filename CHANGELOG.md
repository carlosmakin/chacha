# Changelog

## [1.2.4] - 2024-07-23

### Changed
- **Documentation Updates**: Updated `README.md` and `CHANGELOG.md` to include recent changes and enhancements.
- **Performance Improvements**: Made significant updates to `chacha20.dart` and `poly1305.dart` for improved performance.

## [1.2.0] - 2024-05-27
### Added
- **Benchmark Utilities**: Introduced `benchmark_utilities.dart` for enhanced performance testing and benchmarking.
- **Benchmark Files**: Added `poly1305_benchmark.dart` and `chacha20_poly1305_benchmark.dart` to support detailed benchmarking of cryptographic algorithms.

### Changed
- **Migration to Converter Pattern**: Migrated `chacha20_poly1305` to utilize a converter pattern, improving modularity and code readability.
- **Documentation Updates**: Updated `README.md` and `CHANGELOG.md` to include recent changes and enhancements.
- **Performance Improvements**: Made significant updates to `chacha20_poly1305_benchmark.dart` for improved benchmarking accuracy and performance.
- **File Reorganization**: Renamed and moved files for better maintainability, including the refactoring of `chacha20_aead.dart` to `chacha20_poly1305.dart`.

## [1.1.0] - 2024-05-25
### Added
- **Initial Benchmarks**: Added initial benchmarking scripts for `chacha20` and `poly1305`, including `benchmark.dart` and `chacha20_benchmark.dart`.

### Changed
- **Documentation Enhancements**: Improved `README.md` with additional documentation and usage examples for better clarity.
- **Dependency Updates**: Updated `pubspec.yaml` with new dependencies and configuration settings to support recent changes.
- **Code Refactoring**: Refactored `chacha20_poly1305` (formerly `chacha20_aead`) for improved consistency and maintainability.

## [1.0.1] - 2024-02-25
### Changed
- **Optimization**: Minor optimizations and performance improvements in `poly1305.dart`.
- **Code Updates**: Ongoing updates to `chacha20.dart` for enhanced efficiency and clarity.

## [1.0.0] - 2024-02-10
### Added
- **Core Functionality**: Initial release featuring core functionalities including:
  - **ChaCha20**: Implementation of the ChaCha20 encryption algorithm.
  - **AEAD**: Implementation of Authenticated Encryption with Associated Data (AEAD) using ChaCha20.
  - **Poly1305**: Implementation of the Poly1305 message authentication code.
- **Testing**: Comprehensive test suites for `chacha20`, `chacha20_aead`, and `poly1305` to ensure code reliability.
- **Documentation**: Essential project documentation including `README.md`, `CHANGELOG.md`, and `LICENSE`.
- **Project Setup**: Initial project structure with foundational Dart files and configurations.

### Changed
- **Performance Enhancements**: Regular updates to improve encryption algorithm performance and documentation clarity.

## [0.1.0] - 2024-01-22
### Added
- **Project Initialization**: Initial commit establishing the project foundation:
  - **Configuration Files**: Added `.gitignore`, `analysis_options.yaml`, and initial `pubspec.yaml`.
  - **Core Dart Files**: Established primary Dart files for `chacha20`, `chacha20_aead`, `poly1305`, and `secure_equality.dart`.
  - **Testing Framework**: Initial test files to ensure the correctness of cryptographic implementations.
  - **Documentation**: Created initial `README.md` and `CHANGELOG.md` for project overview and change tracking.

### Changed
- **Initial Setup**: Set up the foundational files and documentation to kickstart the project.