import 'lib/aes.dart';

void main(List<String> args) {
  var key = new AesSymmetricKey.blogExampleKey();
  var encryptor = new AesEncrypt(key);

  var encryptedString = encryptor.blogExample();

  print("Encryption result: " + encryptedString);
  print("Encryption key: " + key.toString());
}
