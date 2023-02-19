package org.honton.chas.jca.vault.provider.keygen.rsa;

import java.time.Duration;
import org.honton.chas.jca.vault.provider.keygen.VaultParameterSpec;

public class VaultRsaParameterSpec extends VaultParameterSpec<VaultRsaKeyAlgorithm> {

  public VaultRsaParameterSpec(String name, VaultRsaKeyAlgorithm keyType) {
    super(name, keyType, null);
  }

  public VaultRsaParameterSpec(String name, VaultRsaKeyAlgorithm keyType, Duration rotation) {
    super(name, keyType, rotation);
  }
}
