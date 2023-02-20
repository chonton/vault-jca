package org.honton.chas.jca.vault.provider.keygen;

import java.time.Duration;

public interface VaultKeyInfo extends VaultParameterSpec {
  /** The name of the key in Vault */
  String getKeyName();

  /** The auto rotate duration. Minimum of 1 Hour */
  Duration getRotation();
}
