package org.honton.chas.jca.vault.provider.keygen.rsa;

import org.honton.chas.jca.vault.provider.keygen.VaultKeyGenerator;

public class VaultRsaKeyGenerator extends VaultKeyGenerator<VaultRsaParameterSpec> {

  public VaultRsaKeyGenerator() {
    super(VaultRsaParameterSpec.class);
  }
}
