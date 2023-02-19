package org.honton.chas.jca.vault.provider.keygen.rsa;

import org.honton.chas.jca.vault.provider.keygen.VaultKeyGenerator;
import org.honton.chas.vault.api.VaultApi;

public class VaultRsaKeyGenerator extends VaultKeyGenerator<VaultRsaKeyAlgorithm, VaultRsaParameterSpec> {

  public VaultRsaKeyGenerator(VaultApi vaultApi) {
    super(vaultApi, VaultRsaParameterSpec.class);
  }
}
