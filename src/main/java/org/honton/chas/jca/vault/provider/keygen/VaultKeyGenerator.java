package org.honton.chas.jca.vault.provider.keygen;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Duration;
import lombok.NonNull;
import org.honton.chas.vault.api.VaultApi;

public class VaultKeyGenerator<K extends VaultKeyAlgorithm, P extends VaultParameterSpec<K>> extends KeyPairGeneratorSpi {

  private final VaultApi vaultApi;
  private final Class<P> vaultParameterSpecClass;

  private P vaultParameterSpec;
  private String rotation;

  protected VaultKeyGenerator(@NonNull VaultApi vaultApi, @NonNull Class<P> vaultParameterSpecClass) {
    this.vaultApi = vaultApi;
    this.vaultParameterSpecClass=vaultParameterSpecClass;
  }

  /**
   * Initializes the key pair generator for a certain keysize, using the default parameter set.
   *
   * @param keysize the keysize. This is an algorithm-specific metric, such as modulus length,
   *     specified in number of bits.
   * @param random the source of randomness for this generator.
   * @throws InvalidParameterException if the {@code keysize} is not supported by this
   *     KeyPairGeneratorSpi object.
   */
  @Override
  public void initialize(int keysize, SecureRandom random) {
    throw new UnsupportedOperationException("initialize with VaultParameterSpec");
  }

  /**
   * Initializes the key pair generator using the specified parameter set and user-provided source
   * of randomness.
   *
   * <p>This concrete method has been added to this previously-defined abstract class. (For
   * backwards compatibility, it cannot be abstract.) It may be overridden by a provider to
   * initialize the key pair generator. Such an override is expected to throw an
   * InvalidAlgorithmParameterException if a parameter is inappropriate for this key pair generator.
   * If this method is not overridden, it always throws an UnsupportedOperationException.
   *
   * @param params the parameter set used to generate the keys.
   * @param random the source of randomness for this generator.
   * @throws InvalidAlgorithmParameterException if the given parameters are inappropriate for this
   *     key pair generator.
   * @since 1.2
   */
  @Override
  public void initialize(@NonNull AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {

    vaultParameterSpec = vaultParameterSpecClass.cast(params);
    rotation = rotationAsString(vaultParameterSpec.getRotation());
  }

  /**
   * Generates a key pair. Unless an initialization method is called using a KeyPairGenerator
   * interface, algorithm-specific defaults will be used. This will generate a new key pair every
   * time it is called.
   *
   * @return the newly generated {@code KeyPair}
   */
  @Override
  public KeyPair generateKeyPair() {
    if (vaultParameterSpec == null) {
      throw new IllegalStateException("must initialize with " + vaultParameterSpecClass.getSimpleName());
    }

    String name = vaultParameterSpec.getName();
    vaultApi.createKey(name, vaultParameterSpec.getVaultType(), rotation);

    return VaultKeyFactory.createKeyPair(name, vaultApi.readKey(name));
  }

  private String rotationAsString(Duration rotation) throws InvalidAlgorithmParameterException {
    if (rotation == null) {
      return "0";
    }

    StringBuilder duration = new StringBuilder();

    long days = rotation.toDays();
    if (days > 0) {
      duration.append(days).append("d");
      rotation = rotation.minusDays(days);
    }

    long hours = rotation.toHours();
    if (hours > 0) {
      duration.append(hours).append("h");
    }

    if (duration.length() == 0) {
      throw new InvalidAlgorithmParameterException("duration must be greater than 1 hour");
    }

    return duration.toString();
  }
}
