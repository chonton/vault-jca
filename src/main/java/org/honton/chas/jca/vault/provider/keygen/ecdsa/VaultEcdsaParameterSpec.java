package org.honton.chas.jca.vault.provider.keygen.ecdsa;

import java.security.spec.ECParameterSpec;
import java.time.Duration;
import lombok.Getter;
import org.honton.chas.jca.vault.provider.keygen.VaultKeyInfo;

@Getter
public class VaultEcdsaParameterSpec extends ECParameterSpec implements VaultKeyInfo {

  private final String keyName;
  private final String keyType;
  private final Duration rotation;

  public VaultEcdsaParameterSpec(String name, VaultEcdsaKeyAlgorithm ka) {
    this(name, ka, null);
  }

  public VaultEcdsaParameterSpec(String keyName, VaultEcdsaKeyAlgorithm ka, Duration rotation) {
    super(ka.curve, ka.g, ka.n, ka.h);
    this.keyName = keyName;
    this.keyType = ka.getKeyType();
    this.rotation = rotation;
  }
}
