import 'dart:math';

import 'dart:typed_data';

// Symmetric key container, includes key generation methods
class AesSymmetricKey {
  late ByteData _keyBytes;

  AesSymmetricKey() {
    _keyBytes = new ByteData(128);
    var rng = Random.secure();
    for (var i = 0; i < 128; i++) {
      _keyBytes.setInt8(i, rng.nextInt(255));
    }
  }
  AesSymmetricKey.fromKeyFile() {}
  AesSymmetricKey.fromKeyString() {}
}

// Utility class for aes byte encryption
class AesEncrypt {}

// Utility class for aes message decryption
class AesDecrypt {}

// Container class for encrypted blocks
class EncryptedMessage {}

// Encrypted block of 16 bytes
class EncryptedBlock {}

// Implements Rijndael Key Schedule for key expansion
class ExpandedKey {}

// Represents a single round key
class RoundKey {}

// Contains addRoundKey, substituteBytes, shiftRows and mixColumns
class AesOperations {}

class SboxCreator {
  late List<int> _logTable;
  // Anti-log is exponentiation table
  late List<int> _antiLogTable;
  late List<int> _sBox;
  final int _generator = 0xe5;
  final int _fieldLimit = 256;

  SboxCreator() {
    _logTable = new List.generate(this._fieldLimit, (index) => 0);
    _antiLogTable = new List.generate(this._fieldLimit, (index) => 0);
    _sBox = new List.generate(this._fieldLimit, (index) => 0);
  }

  void initialize() {
    this._populateLogAndAntilog();
    this._fillSboxWithMultiplicativeInverse();
    this._applyAffineTransformToSbox();
  }

  void _populateLogAndAntilog() {
    int product = 1;

    for (var i = 0; i < this._fieldLimit; i++) {
      _logTable[product] = i;
      _antiLogTable[i] = product;
      product = this.galoisMultiplication(_generator, _antiLogTable[i]);
    }
  }

  void _fillSboxWithMultiplicativeInverse() {
    for (var i = 1; i < this._fieldLimit; i++) {
      this._sBox[i] = this._antiLogTable[255 - this._logTable[i]];
    }
  }

  void _applyAffineTransformToSbox() {
    for (var i = 0; i < _fieldLimit; i++) {
      var x = _sBox[i];
      var s = _sBox[i];

      for (var j = 0; j < 4; j++) {
        s = (s << 1) | (s >> 7);
        x ^= s;
      }

      x ^= 0x63;
      _sBox[i] = x % _fieldLimit;
    }
  }

  int galoisMultiplication(int a, int b) {
    int p = 0;
    int highBitSet;
    for (var i = 0; i < 8; i++) {
      if ((b & 1) == 1) {
        p ^= a;
      }
      highBitSet = (a & 0x80);
      a <<= 1;
      if (highBitSet == 0x80) {
        a ^= 0x1b;
      }
      b >>= 1;
    }

    // Convert back to unsigned 8 bit int
    return p % this._fieldLimit;
  }
}
