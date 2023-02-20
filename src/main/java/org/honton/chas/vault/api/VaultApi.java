package org.honton.chas.vault.api;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

public interface VaultApi {

  static void setVaultInstance(String vaultAddress, Supplier<String> vaultToken) {
    VaultClient.setVaultInstance(vaultAddress, vaultToken);
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
