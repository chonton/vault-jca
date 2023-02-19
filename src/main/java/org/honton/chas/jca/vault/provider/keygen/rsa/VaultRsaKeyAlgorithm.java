package org.honton.chas.jca.vault.provider.keygen.rsa;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.honton.chas.jca.vault.provider.keygen.VaultKeyAlgorithm;

@RequiredArgsConstructor
public enum VaultRsaKeyAlgorithm implements VaultKeyAlgorithm {
  // RSA with bit size of 2048
  RSA_2048("rsa-2048"),
  // RSA with bit size of 3072
  RSA_3072("rsa-3072"),
  // RSA with bit size of 4096
  RSA_4096("rsa-4096");

  @Getter private final String vaultKeyType;
}
