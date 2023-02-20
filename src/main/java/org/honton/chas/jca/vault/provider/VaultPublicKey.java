package org.honton.chas.jca.vault.provider;

import java.security.PublicKey;

public abstract class VaultPublicKey extends VaultKey implements PublicKey {

  protected VaultPublicKey(String name, int version) {
    super(name, version);
  }
}
