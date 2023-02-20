package org.honton.chas.jca.vault.provider.keygen.rsa;

import lombok.Getter;
import org.honton.chas.jca.vault.provider.keygen.VaultParameterSpec;

public enum VaultRsaKeyType implements VaultParameterSpec {
  // RSA with bit size of 2048
  RSA_2048,
  // RSA with bit size of 3072
  RSA_3072,
  // RSA with bit size of 4096
  RSA_4096;

  @Getter private final String keyType;
  @Getter private final int bits;

  VaultRsaKeyType() {
    this.bits = Integer.parseInt(name().substring(4));
    this.keyType = "rsa-" + bits;
  }
}
