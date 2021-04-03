import 'lib/aes.dart';

void main(List<String> args) {
  String msg = "Two One Nine Two";
  var key = new AesSymmetricKey();
  var encryptor = new AesEncrypt(key);
  var encryptedString = encryptor.encrypt(msg);
  print("Encryption result: " + encryptedString);
  print("Encryption key: " + key.toString());
}
