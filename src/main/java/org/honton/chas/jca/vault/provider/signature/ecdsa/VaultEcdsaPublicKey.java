package org.honton.chas.jca.vault.provider.signature.ecdsa;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import org.honton.chas.jca.vault.provider.VaultPublicKey;

public class VaultEcdsaPublicKey extends VaultPublicKey implements ECPublicKey {

  private final transient ECPublicKey delegate;

  public VaultEcdsaPublicKey(String name, int version, ECPublicKey delegate) {
    super(name, version);
    this.delegate = delegate;
  }

  @Override
  public ECPoint getW() {
    return delegate.getW();
  }

  @Override
  public String getAlgorithm() {
    return delegate.getAlgorithm();
  }

  @Override
  public String getFormat() {
    return delegate.getFormat();
  }

  @Override
  public byte[] getEncoded() {
    return delegate.getEncoded();
  }

  @Override
  public ECParameterSpec getParams() {
    return delegate.getParams();
  }
}
