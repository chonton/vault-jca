package org.honton.chas.jca.vault.provider.keygen.ecdsa;

import org.honton.chas.jca.vault.provider.keygen.VaultKeyGenerator;

public class VaultEcdsaKeyGenerator extends VaultKeyGenerator<VaultEcdsaParameterSpec> {

  public VaultEcdsaKeyGenerator() {
    super(VaultEcdsaParameterSpec.class);
  }
}
