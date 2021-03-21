import 'lib/aes.dart';

void main(List<String> args) {
  // var test = new AesSymmetricKey();
  var galois = new SboxCreator();
  galois.initialize();
}
