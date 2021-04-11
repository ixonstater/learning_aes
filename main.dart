import 'lib/aes.dart';

void main(List<String> args) {
  // String msg = "hello";
  // var key = new AesSymmetricKey();
  // var encryptor = new AesEncrypt(key);

  // var start = DateTime.now();
  // var encryptedString = encryptor.encrypt(msg);
  // var end = DateTime.now();
  // var interval = end.difference(start).inMilliseconds;

  // print("Encryption result: " + encryptedString);
  // print("Encryption key: " + key.toString());
  // print("Encryption took: " + interval.toString());
  //
  var sbox = new Sbox();
  print("");
  sbox.printSbox();
}
