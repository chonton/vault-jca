package org.honton.chas.jca.vault.provider.keygen;

import java.security.spec.AlgorithmParameterSpec;

public interface VaultParameterSpec extends AlgorithmParameterSpec {
  /** Vault's name for the key type */
  String getKeyType();
}
