import 'dart:math';

// Symmetric key container, includes key generation methods
class AesSymmetricKey {
  late List<int> _keyBytes;

  AesSymmetricKey() {
    // var rng = Random.secure();
    // _keyBytes = List.generate(16, (index) => rng.nextInt(255));
    _keyBytes = [
      0x0f,
      0x15,
      0x71,
      0xc9,
      0x47,
      0xd9,
      0xe8,
      0x59,
      0x0c,
      0xb7,
      0xad,
      0xd6,
      0xaf,
      0x7f,
      0x67,
      0x98
    ];
  }
  AesSymmetricKey.fromKeyFile() {}
  AesSymmetricKey.fromKeyString() {}

  List<int> getBytes(int start, int end) {
    return this._keyBytes.sublist(start, end);
  }
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
class ExpandedKey {
  List<Word> _words = [];
  Word _roundConstant = new Word.fromByteArray([1, 0, 0, 0]);
  Sbox _sbox;

  ExpandedKey(AesSymmetricKey key, this._sbox) {
    for (var i = 0; i < 4; i++) {
      var start = i * 4;
      var end = start + 4;
      this._words.add(new Word.fromByteArray(key.getBytes(start, end)));
    }
  }

  void expand() {
    for (var roundNumber = 1; roundNumber < 11; roundNumber++) {
      for (var wordNumber = 0; wordNumber < 4; wordNumber++) {
        var previousWord = this._words[roundNumber * 4 + wordNumber - 1];
        var fourWordsAgo = this._words[roundNumber * 4 + wordNumber - 4];
        if (wordNumber == 0) {
          this.modifyFirstWordInRoundKey(previousWord);
        }
        this._words.add(previousWord ^ fourWordsAgo);
      }
    }
  }

  void modifyFirstWordInRoundKey(Word word) {
    word << 1;
    for (var i = 0; i < 4; i++) {
      word.bytes[i] = this._sbox.substitute(word.bytes[i]);
    }
    word.xorEquals(this._roundConstant);
    this._roundConstant.bytes[0] =
        this._sbox.galoisMultiplication(2, this._roundConstant.bytes[0]);
  }

  void getRoundKey(int round) {}
}

// Represents a single round key word
class Word {
  List<int> bytes = new List.generate(4, (index) => 0);

  Word() {}

  Word.fromByteArray(List<int> bytes) {
    this.bytes = bytes;
  }

  Word operator ^(Word op) {
    Word result = new Word();
    for (var i = 0; i < 4; i++) {
      result.bytes[i] = this.bytes[i] ^ op.bytes[i];
    }

    return result;
  }

  void xorEquals(Word op) {
    for (var i = 0; i < 4; i++) {
      this.bytes[i] = this.bytes[i] ^ op.bytes[i];
    }
  }

  void operator <<(int shift) {
    var newBytes = this.bytes.sublist(shift);
    newBytes.addAll(this.bytes.sublist(0, shift));
    this.bytes = newBytes;
  }

  void printWord() {
    this.bytes.forEach((element) {
      print(element.toRadixString(16));
    });
  }
}

// Contains addRoundKey, substituteBytes, shiftRows and mixColumns
class AesOperations {}

class Sbox {
  late List<int> _logTable;
  // Anti-log is exponentiation table
  late List<int> _antiLogTable;
  late List<int> _sBox;
  final int _generator = 0xe5;
  final int _fieldLimit = 256;

  Sbox() {
    _logTable = new List.generate(this._fieldLimit, (index) => 0);
    _antiLogTable = new List.generate(this._fieldLimit, (index) => 0);
    _sBox = new List.generate(this._fieldLimit, (index) => 0);
    this._initialize();
  }

  void _initialize() {
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

  int substitute(int a) {
    return this._sBox[a];
  }
}
