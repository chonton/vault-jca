package org.honton.chas.jca.vault.provider.keygen;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

@UtilityClass
public class Pkcs8 {

  private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n";
  private static final String END_PUBLIC_KEY = "\n-----END PUBLIC KEY-----";

  @SneakyThrows
  public PublicKey getPublicKeyFromString(String pem) {
    int start = pem.indexOf(BEGIN_PUBLIC_KEY) + BEGIN_PUBLIC_KEY.length();
    int end = pem.indexOf(END_PUBLIC_KEY);
    String interesting = pem.substring(start, end);
    byte[] encoded = Base64.getMimeDecoder().decode(interesting);

    KeyFactory kf = KeyFactory.getInstance(interesting.startsWith("MII") ?"RSA" :"EC");
    return kf.generatePublic(new X509EncodedKeySpec(encoded));
  }

}
