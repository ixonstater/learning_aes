import 'lib/aes.dart';

void main(List<String> args) {
  String msg = "";
  var key = new AesSymmetricKey();
  var encryptor = new AesEncrypt(key);
  encryptor.encrypt(msg);
}
