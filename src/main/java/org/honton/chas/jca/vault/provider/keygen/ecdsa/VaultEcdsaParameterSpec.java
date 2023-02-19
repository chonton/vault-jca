package org.honton.chas.jca.vault.provider.keygen.ecdsa;

import java.time.Duration;
import org.honton.chas.jca.vault.provider.keygen.VaultParameterSpec;

public class VaultEcdsaParameterSpec extends VaultParameterSpec<VaultEcdsaKeyAlgorithm> {

   public VaultEcdsaParameterSpec(String name, VaultEcdsaKeyAlgorithm keyType) {
    super(name, keyType, null);
  }

  public VaultEcdsaParameterSpec(String name, VaultEcdsaKeyAlgorithm keyType,
      Duration rotation) {
    super(name, keyType, rotation);
  }
}
