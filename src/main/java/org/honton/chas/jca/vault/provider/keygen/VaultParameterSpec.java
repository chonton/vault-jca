package org.honton.chas.jca.vault.provider.keygen;

import java.security.spec.AlgorithmParameterSpec;
import java.time.Duration;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

@AllArgsConstructor
@Getter
public class VaultParameterSpec<T extends VaultKeyAlgorithm> implements AlgorithmParameterSpec {

  /** The name of the stored key */
  @NonNull String name;

  @NonNull T keyType;

  /** The auto rotate duration. Minimum of 1 Hour */
  Duration rotation;

  public final String getVaultType() {
    return keyType.getVaultKeyType();
  }
}
