import 'lib/aes.dart';

void main(List<String> args) {
  var test = new AesSymmetricKey();
  var box = new Sbox();
  var expanded = new ExpandedKey(test, box);
  expanded.expand();
}
