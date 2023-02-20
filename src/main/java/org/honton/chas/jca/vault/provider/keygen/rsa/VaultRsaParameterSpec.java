package org.honton.chas.jca.vault.provider.keygen.rsa;

import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Duration;
import lombok.Getter;
import org.honton.chas.jca.vault.provider.keygen.VaultKeyInfo;

@Getter
public class VaultRsaParameterSpec extends RSAKeyGenParameterSpec implements VaultKeyInfo {

  private final String keyName;
  private final String keyType;
  private final Duration rotation;

  public VaultRsaParameterSpec(String name, VaultRsaKeyType vaultKeyType) {
    this(name, vaultKeyType, null);
  }

  public VaultRsaParameterSpec(String keyName, VaultRsaKeyType keyType, Duration rotation) {
    super(keyType.getBits(), RSAKeyGenParameterSpec.F0);
    this.keyName = keyName;
    this.keyType = keyType.getKeyType();
    this.rotation = rotation;
  }
}
