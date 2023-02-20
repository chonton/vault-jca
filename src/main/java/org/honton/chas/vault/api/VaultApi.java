package org.honton.chas.vault.api;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

public interface VaultApi {

  static void setVaultInstance(String vaultAddress, String vaultToken) {
    VaultClient.setVaultInstance(vaultAddress, vaultToken);
  }

  static <T> T walkPath(Object result, String... pathSegments) {
    for (String pathSegment : pathSegments) {
      result = ((Map) result).get(pathSegment);
    }
    return (T) result;
  }

  /**
   * List all keys in the transit engine
   *
   * @return List of Key names
   */
  List<String> listKeys();

  void createKey(String name, String keyType, String autoRotationPeriod);

  /**
   * Get a key from the transit engine
   *
   * @param name The name of the key
   * @return The key information
   */
  Map<String, Object> readKey(String name);

  byte[] signData(
      String name, int version, String signatureAlgorithm, String hashAlgorithm, ByteBuffer data);

  boolean verifySignedData(
      String name,
      int version,
      String signatureAlgorithm,
      String hashAlgorithm,
      ByteBuffer data,
      byte[] signature);
}
