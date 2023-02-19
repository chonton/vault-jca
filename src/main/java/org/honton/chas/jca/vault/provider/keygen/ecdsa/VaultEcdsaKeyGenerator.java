package org.honton.chas.jca.vault.provider.keygen.ecdsa;

import org.honton.chas.jca.vault.provider.keygen.VaultKeyGenerator;
import org.honton.chas.vault.api.VaultApi;

public class VaultEcdsaKeyGenerator extends VaultKeyGenerator<VaultEcdsaKeyAlgorithm, VaultEcdsaParameterSpec> {

  public VaultEcdsaKeyGenerator(VaultApi vaultApi) {
    super(vaultApi, VaultEcdsaParameterSpec.class);
  }
}
