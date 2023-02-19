package org.honton.chas.jca.vault.provider.keygen.ecdsa;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.honton.chas.jca.vault.provider.keygen.VaultKeyAlgorithm;

@RequiredArgsConstructor
public enum VaultEcdsaKeyAlgorithm implements VaultKeyAlgorithm {
  // ECDSA with P-256 elliptic curve
  ECDSA_P256("ecdsa-p256"),
  // ECDSA with P-384 elliptic curve
  ECDSA_P384("ecdsa-p384"),
  // ECDSA with P-521 elliptic curve
  ECDSA_P521("ecdsa-p521");

  @Getter private final String vaultKeyType;
}
