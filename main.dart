import 'lib/aes.dart';

void main(List<String> args) {
  var key = new AesSymmetricKey();
  var encryptor = new AesEncrypt(key);

  var encryptedString = encryptor.encrypt("");

  print("Encryption result: " + encryptedString);
  print("Encryption key: " + key.toString());
}
