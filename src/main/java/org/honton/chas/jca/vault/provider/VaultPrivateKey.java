package org.honton.chas.jca.vault.provider;

import java.security.PrivateKey;

public abstract class VaultPrivateKey extends VaultKey implements PrivateKey {

  protected VaultPrivateKey(String name, int version) {
    super(name, version);
  }

  protected static <T> T noExport() {
    throw new UnsupportedOperationException("No export of private key outside vault");
  }

  @Override
  public byte[] getEncoded() {
    return noExport();
  }
}
