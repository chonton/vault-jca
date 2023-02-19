package org.honton.chas.jca.vault.provider;

import java.security.Provider;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import lombok.NonNull;
import org.honton.chas.jca.vault.provider.keygen.VaultKeyGenerator;
import org.honton.chas.jca.vault.provider.keygen.VaultKeyAlgorithm;
import org.honton.chas.jca.vault.provider.keygen.VaultParameterSpec;
import org.honton.chas.jca.vault.provider.keygen.ecdsa.VaultEcdsaKeyGenerator;
import org.honton.chas.jca.vault.provider.keygen.rsa.VaultRsaKeyGenerator;
import org.honton.chas.jca.vault.provider.keystore.VaultKeyStore;
import org.honton.chas.jca.vault.provider.signature.SignatureAlgorithm;
import org.honton.chas.jca.vault.provider.signature.VaultSignature;
import org.honton.chas.vault.api.VaultApi;

public final class VaultProvider extends Provider {

  private final VaultApi vaultApi;

  public VaultProvider(@NonNull VaultApi vaultApi) {
    super("Vault", "1.0", "Hashicorp Vault Provider");
    this.vaultApi = vaultApi;

    putService(
        new VaultKeyPairGeneratorService<>(
            "RSA", VaultRsaKeyGenerator.class, VaultRsaKeyGenerator::new));
    putService(
        new VaultKeyPairGeneratorService<>(
            "RSASSA-PSS", VaultRsaKeyGenerator.class, VaultRsaKeyGenerator::new));
    putService(
        new VaultKeyPairGeneratorService<>(
            "EC", VaultEcdsaKeyGenerator.class, VaultEcdsaKeyGenerator::new));

    putService(new VaultKeyStoreService());

    for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
      putService(new VaultSignatureService(algorithm));
    }
  }

  /*
  Provider is a Properties! We should provide a better equals / hashCode
   */
  @Override
  @SuppressWarnings("java:S3551") // don't make method synchronized
  public boolean equals(Object o) {
    return o instanceof VaultProvider && vaultApi.equals(((VaultProvider) o).vaultApi);
  }

  @Override
  @SuppressWarnings("java:S3551") // don't make method synchronized
  public int hashCode() {
    return vaultApi.hashCode();
  }

  private class VaultKeyStoreService extends Service {
    private VaultKeyStoreService() {
      super(
          VaultProvider.this,
          "KeyStore",
          "Vault",
          VaultKeyStore.class.getName(),
          List.of(),
          Map.of());
    }

    @Override
    public Object newInstance(Object constructorParameter) {
      return new VaultKeyStore(vaultApi);
    }
  }

  private class VaultKeyPairGeneratorService<
          K extends VaultKeyAlgorithm,
          P extends VaultParameterSpec<K>,
          T extends VaultKeyGenerator<K, P>>
      extends Service {

    Function<VaultApi, T> ctr;

    private VaultKeyPairGeneratorService(
        String keyPairGeneratorAlgorithm, Class<T> generatorClass, Function<VaultApi, T> ctr) {
      super(
          VaultProvider.this,
          "KeyPairGenerator",
          keyPairGeneratorAlgorithm,
          generatorClass.getName(),
          List.of(),
          Map.of());
      this.ctr = ctr;
    }

    @Override
    public Object newInstance(Object constructorParameter) {
      return ctr.apply(vaultApi);
    }
  }

  private class VaultSignatureService extends Service {

    private final SignatureAlgorithm algorithm;

    private VaultSignatureService(SignatureAlgorithm algorithm) {
      super(
          VaultProvider.this,
          "Signature",
          algorithm.getJcaSignatureAlgorithm(),
          VaultSignature.class.getName(),
          List.of(),
          Map.of());
      this.algorithm = algorithm;
    }

    @Override
    public Object newInstance(Object constructorParameter) {
      return new VaultSignature(vaultApi, algorithm);
    }
  }
}
