package org.honton.chas.jca.vault.provider.signature.rsa;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import org.honton.chas.jca.vault.provider.VaultPublicKey;

public class VaultRsaPublicKey extends VaultPublicKey implements RSAPublicKey {

  private final transient RSAPublicKey delegate;

  public VaultRsaPublicKey(String name, int version, RSAPublicKey delegate) {
    super(name, version);
    this.delegate = delegate;
  }

  @Override
  public BigInteger getPublicExponent() {
    return delegate.getPublicExponent();
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
  public BigInteger getModulus() {
    return delegate.getModulus();
  }
}
