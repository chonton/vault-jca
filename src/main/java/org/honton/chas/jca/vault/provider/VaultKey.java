package org.honton.chas.jca.vault.provider;

import java.security.Key;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/** A Key stored in Vault Transit Secrets Engine */
@Getter
@RequiredArgsConstructor
@EqualsAndHashCode
public abstract class VaultKey implements Key {

  /**
   * Name of key
   */
  @NonNull private final String name;

  /**
   * Version of key
   */
  private final int version;
}
