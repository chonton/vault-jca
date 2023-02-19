package org.honton.chas.jca.vault.provider.keygen;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Map.Entry;
import lombok.experimental.UtilityClass;
import org.honton.chas.jca.vault.provider.VaultPublicKey;
import org.honton.chas.jca.vault.provider.signature.ecdsa.VaultEcdsaPrivateKey;
import org.honton.chas.jca.vault.provider.signature.ecdsa.VaultEcdsaPublicKey;
import org.honton.chas.jca.vault.provider.signature.rsa.VaultRsaPrivateKey;
import org.honton.chas.jca.vault.provider.signature.rsa.VaultRsaPublicKey;
import org.honton.chas.vault.api.VaultApi;

@UtilityClass
public class VaultKeyFactory {

  KeyPair createKeyPair(String name, Map<String, Object> result) {
    VaultPublicKey publicKey = wrapPublicKey(name, result);
    PrivateKey privateKey = wrapPrivateKey(publicKey);
    return new KeyPair(publicKey, privateKey);
  }

  public VaultPublicKey wrapPublicKey(String name, Map<String, Object> result) {
    Entry<String, Map<String, String>> latestKey = latestKey(result);
    PublicKey publicKey = getPublicKey(latestKey.getValue());
    int version = Integer.parseInt(latestKey.getKey());

    String type = VaultApi.walkPath(result, "type");
    if (type.startsWith("rsa-")) {
      return new VaultRsaPublicKey(name, version, (RSAPublicKey) publicKey);
    }
    if (type.startsWith("ecdsa-")) {
      return new VaultEcdsaPublicKey(name, version, (ECPublicKey) publicKey);
    }
    throw new UnsupportedOperationException("Unsupported key type " + type);
  }

  private static PrivateKey wrapPrivateKey(VaultPublicKey publicKey) {
    if (publicKey instanceof VaultRsaPublicKey) {
      return new VaultRsaPrivateKey(publicKey.getName(), publicKey.getVersion());
    }
    if (publicKey instanceof VaultEcdsaPublicKey) {
      return new VaultEcdsaPrivateKey(publicKey.getName(), publicKey.getVersion());
    }
    throw new UnsupportedOperationException("Unsupported key type ");
  }

  private Entry<String, Map<String, String>> latestKey(Map<String, Object> result) {
    Map<String, Map<String, String>> keys = VaultApi.walkPath(result, "keys");
    return keys.entrySet().stream().reduce(VaultKeyFactory::max).orElseThrow();
  }

  private Entry<String, Map<String, String>> max(
      Entry<String, Map<String, String>> l, Entry<String, Map<String, String>> r) {
    return Integer.parseInt(l.getKey()) > Integer.parseInt(r.getKey()) ? l : r;
  }

  private PublicKey getPublicKey(Map<String, String> key) {
    return Pkcs8.getPublicKeyFromString(key.get("public_key"));
  }
}
