package org.honton.chas.jca.vault.provider;

import lombok.experimental.UtilityClass;
import org.honton.chas.vault.api.VaultApi;
import org.junit.jupiter.api.Assertions;

@UtilityClass
public class VaultApiFactory {

  private String getRootToken() {
    /*
    That's amazing! I've got the same combination on my luggage.
        - President Skroob  https://www.youtube.com/watch?v=li9Qf-nQgWE
    */
    return "12345";
  }

  private String getVaultAddr() {
    String vaultPort = System.getenv("VAULT_PORT");
    Assertions.assertNotNull(vaultPort);
    return "http://localhost:" + vaultPort;
  }

  public VaultProvider getVaultProvider() {
    VaultApi vaultApi = VaultApi.getVaultInstance(getVaultAddr(), getRootToken());
    return new VaultProvider(vaultApi);
  }
}
