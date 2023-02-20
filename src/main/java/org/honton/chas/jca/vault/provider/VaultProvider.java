package org.honton.chas.jca.vault.provider;

import java.nio.file.ProviderNotFoundException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.function.Supplier;
import org.honton.chas.jca.vault.provider.keygen.VaultKeyGenerator;
import org.honton.chas.jca.vault.provider.keygen.VaultKeyInfo;
import org.honton.chas.jca.vault.provider.keygen.ecdsa.VaultEcdsaKeyGenerator;
import org.honton.chas.jca.vault.provider.keygen.rsa.VaultRsaKeyGenerator;
import org.honton.chas.jca.vault.provider.keystore.VaultKeyStore;
import org.honton.chas.jca.vault.provider.signature.SignatureAlgorithm;
import org.honton.chas.jca.vault.provider.signature.VaultSignature;

public final class VaultProvider extends Provider {

  public static final String NAME = "Vault";

  public VaultProvider() {
    super(NAME, "1.0", "Hashicorp Vault Provider");

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

  public static Provider register() {
    Provider vault = Security.getProvider(NAME);
    if (vault == null) {
      ServiceLoader<Provider> sl = ServiceLoader.load(java.security.Provider.class);
      vault =
          sl.stream()
              .filter(pp -> pp.get().getName().equals(NAME))
              .findFirst()
              .orElseThrow(() -> new ProviderNotFoundException("Vault is missing"))
              .get();
      Security.addProvider(vault);
    }
    return vault;
  }

  /*
  Provider is a Properties! We should provide a better equals / hashCode
   */
  @Override
  @SuppressWarnings("java:S3551") // don't make method synchronized
  public boolean equals(Object o) {
    return o instanceof VaultProvider;
  }

  @Override
  @SuppressWarnings("java:S3551") // don't make method synchronized
  public int hashCode() {
    return getClass().hashCode();
  }

  private class VaultKeyStoreService extends Service {
    private VaultKeyStoreService() {
      super(
          VaultProvider.this, "KeyStore", NAME, VaultKeyStore.class.getName(), List.of(), Map.of());
    }

    @Override
    public Object newInstance(Object constructorParameter) {
      return new VaultKeyStore();
    }
  }

  private class VaultKeyPairGeneratorService<
          P extends AlgorithmParameterSpec & VaultKeyInfo, T extends VaultKeyGenerator<P>>
      extends Service {

    Supplier<T> ctr;

    private VaultKeyPairGeneratorService(
        String keyPairGeneratorAlgorithm, Class<T> generatorClass, Supplier<T> ctr) {
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
      return ctr.get();
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
      return new VaultSignature(algorithm);
    }
  }
}
