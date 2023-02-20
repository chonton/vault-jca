package org.honton.chas.jca.vault.provider.signature.ecdsa;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import lombok.Getter;
import org.honton.chas.jca.vault.provider.VaultPrivateKey;

public class VaultEcdsaPrivateKey extends VaultPrivateKey implements ECPrivateKey {

  @Getter private final ECParameterSpec params;

  public VaultEcdsaPrivateKey(String name, int version, ECParameterSpec params) {
    super(name, version);
    this.params = params;
  }

  @Override
  public BigInteger getS() {
    return noExport();
  }

  @Override
  public String getAlgorithm() {
    return "EC_EC";
  }

  @Override
  public String getFormat() {
    return "PKCS#8";
  }
}
