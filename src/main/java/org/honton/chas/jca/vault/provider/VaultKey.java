package org.honton.chas.jca.vault.provider;

import java.security.Key;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * A Key stored in Vault Transit Secrets Engine
 */
@Getter
@RequiredArgsConstructor
public abstract class VaultKey implements Key {
    @NonNull
    private final String name;
    private final int version;
}
