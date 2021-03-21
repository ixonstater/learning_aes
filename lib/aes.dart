import 'dart:convert';
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

// Utility class for aes message encryption
class AesEncrypt {
  late ExpandedKey _key;
  late Sbox _sbox;

  AesEncrypt(AesSymmetricKey key) {
    var sbox = new Sbox();
    this._sbox = sbox;
    this._key = new ExpandedKey(key, sbox);
  }

  String encrypt(String msg) {
    List<int> data = EncryptedMessage.convertStringToByteArray(msg);
    data = [
      0x01,
      0x23,
      0x45,
      0x67,
      0x89,
      0xab,
      0xcd,
      0xef,
      0xfe,
      0xdc,
      0xba,
      0x98,
      0x76,
      0x54,
      0x32,
      0x10
    ];
    var encryptedMsg = new EncryptedMessage(this._key, data);

    for (var blkNum = 0; blkNum < encryptedMsg.blocks.length; blkNum++) {
      var block = encryptedMsg.blocks[blkNum];
      for (var roundNum = 0; roundNum < 11; roundNum++) {
        if (roundNum == 0) {
          encryptedMsg.addRoundKey(block, roundNum);
        } else if (roundNum == 10) {
          encryptedMsg.substituteBytes(block, this._sbox);
          encryptedMsg.shiftRows(block);
          encryptedMsg.addRoundKey(block, roundNum);
        } else {
          encryptedMsg.substituteBytes(block, this._sbox);
          encryptedMsg.shiftRows(block);
          encryptedMsg.mixColumns(block);
          encryptedMsg.addRoundKey(block, roundNum);
        }
      }
    }

    return "";
  }
}

// Utility class for aes message decryption
class AesDecrypt {}

// Container class for encrypted blocks
class EncryptedMessage {
  List<EncryptedBlock> blocks = [];
  ExpandedKey _key;

  EncryptedMessage(this._key, List<int> data) {
    var bytesProcessed = 0;
    while (bytesProcessed < data.length) {
      if (data.length - bytesProcessed > 16) {
        this.blocks.add(new EncryptedBlock(
            data.sublist(bytesProcessed, bytesProcessed + 16)));
      } else {
        var dataBlock = new List<int>.from(data.sublist(bytesProcessed));
        // Pad last block with zeros
        dataBlock.addAll(new List.generate(
            16 - (data.length - bytesProcessed), (index) => 0));
        this.blocks.add(new EncryptedBlock(dataBlock));
      }

      bytesProcessed += 16;
    }
  }

  static List<int> convertStringToByteArray(String str) {
    return utf8.encode(str);
  }

  void addRoundKey(EncryptedBlock blk, int round) {
    var roundKey = this._key.getRoundKey(round);
    for (var i = 0; i < 4; i++) {
      blk.data[i].xorEquals(roundKey[i]);
    }
  }

  void substituteBytes(EncryptedBlock blk, Sbox box) {
    for (var i = 0; i < 4; i++) {
      box.substitute(blk.data[i]);
    }
  }

  void shiftRows(EncryptedBlock blk) {}

  void mixColumns(EncryptedBlock blk) {}
}

// Encrypted block of 16 bytes
class EncryptedBlock {
  List<Word> data = [];

  EncryptedBlock(List<int> data) {
    for (var i = 0; i < 4; i++) {
      var start = i * 4;
      var end = start + 4;
      this.data.add(new Word.fromByteArray(data.sublist(start, end)));
    }
  }
}

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

    this._expand();
  }

  void _expand() {
    for (var roundNumber = 1; roundNumber < 11; roundNumber++) {
      for (var wordNumber = 0; wordNumber < 4; wordNumber++) {
        // Create a new word here to avoid corrupting previous round keys
        var previousWord = new Word.fromByteArray(
            _words[roundNumber * 4 + wordNumber - 1].bytes);
        var fourWordsAgo = this._words[roundNumber * 4 + wordNumber - 4];
        if (wordNumber == 0) {
          this._modifyFirstWordInRoundKey(previousWord);
        }
        this._words.add(previousWord ^ fourWordsAgo);
      }
    }
  }

  void _modifyFirstWordInRoundKey(Word word) {
    word << 1;
    this._sbox.substitute(word);
    word.xorEquals(this._roundConstant);
    this._roundConstant.bytes[0] =
        this._sbox.galoisMultiplication(2, this._roundConstant.bytes[0]);
  }

  List<Word> getRoundKey(int round) {
    return this._words.sublist(round * 4, round * 4 + 4);
  }
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

// Represents the rijndael byte substitution box
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

  void substitute(Word word) {
    for (var i = 0; i < 4; i++) {
      word.bytes[i] = this._sBox[word.bytes[i]];
    }
  }
}
