import 'dart:convert';

import 'package:cryptography/cryptography.dart';
// ignore: depend_on_referenced_packages
import 'package:convert/convert.dart';

// Use the same key as in GoLang code
const key = "use-openssl-rand--base64--256key";

Future<void> main() async {
  // Encrypt text
  final encText = await encrypt("Hello from Dart");
  print("DartEnc: $encText");

  // Decrypt from GoLang
  final goEncText =
      "6a4de0abafca233567ecc9e36eb77f3b6e8ef80d96bd74ea1e498048925257709991d4897b5cb0626ef88a566a35fc9125ffe272";
  final decText = await decrypt(goEncText);
  print("--------------------");
  print("DartDec: $decText");
}

Future<String> decrypt(String hexEncText) async {
  // Hex -> byte
  final hexCipText = hex.decode(hexEncText);
  // or if base64 is choosen
  //final hexCipText = base64Decode(base64.normalize(hexEncText));

  final algo = AesGcm.with256bits();

/*** This is only for understanding the Seal/SecretBox 
 * Can be commented from here */
  final nonce = hexCipText.sublist(0, 12);
  final int macSize = algo.macAlgorithm.macLength; //16
  final ciphertext = hexCipText.sublist(12, (hexCipText.length - macSize));
  final mac = hexCipText.sublist((hexCipText.length - macSize));

  print("Nonce: ${nonce.length} $nonce");
  print("Cipher: ${ciphertext.length} $ciphertext");
  print("Mac: ${mac.length} $mac");
/*** to here */

  final secretKey = SecretKey(utf8.encode(key));
  SecretBox secretBox = SecretBox.fromConcatenation(hexCipText,
      nonceLength: algo.nonceLength, macLength: algo.macAlgorithm.macLength);

  final decrypted = await algo.decrypt(secretBox, secretKey: secretKey);

  return utf8.decode(decrypted);
}

// Criptare
Future<String> encrypt(String plainText) async {
  final secretKey = SecretKey(utf8.encode(key));
  final algo = AesGcm.with256bits();

  final secretBox =
      await algo.encrypt(utf8.encode(plainText), secretKey: secretKey);

  return hex.encode(secretBox.concatenation());
  // Or base64
  //return base64.normalize(base64Encode(secretBox.concatenation()));
}
