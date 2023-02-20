package org.honton.chas.jca.vault.provider.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import java.io.IOException;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.util.List;
import org.honton.chas.jca.vault.provider.VaultProvider;
import org.honton.chas.jca.vault.provider.oidc.OidcWellKnown.JsonWebKeySet;
import org.jose4j.jwt.GeneralJwtException;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;

@WireMockTest(httpsEnabled = true)
@TestInstance(Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class OpenIdIT {

  private final ConnectProvider connectProvider;
  private final RelyingParty relyingParty;
  private final ObjectMapper mapper;
  private final HttpClient client;

  OpenIdIT() throws JoseException, GeneralSecurityException {
    VaultProvider.register();
    connectProvider = new ConnectProvider();
    relyingParty = new RelyingParty();
    mapper = new ObjectMapper();
    client = ClientFactory.createClient();
  }

  void setupWellknown(WireMockRuntimeInfo wmri) throws IOException {
    String issuer = wmri.getHttpsBaseUrl();
    String cfg = mapper.writeValueAsString(connectProvider.getOpenIdProviderConfiguration(issuer));
    WireMock.stubFor(
        WireMock.get("/.well-known/openid-configuration").willReturn(WireMock.okJson(cfg)));

    String jwks = mapper.writeValueAsString(connectProvider.getJwks());
    WireMock.stubFor(WireMock.get("/.well-known/jwks.json").willReturn(WireMock.okJson(jwks)));
  }

  @Test
  @Order(10)
  void readWellKnown(WireMockRuntimeInfo wmri) throws IOException {
    setupWellknown(wmri);

    String issuer = wmri.getHttpsBaseUrl();
    OidcWellKnown.Configuration cfg = OidcWellKnown.getConfiguration(client, issuer, mapper);

    Assertions.assertEquals(wmri.getHttpsBaseUrl() + "/.well-known/jwks.json", cfg.getJwksUri());

    JsonWebKeySet jwks = OidcWellKnown.getJwks(client, cfg.getJwksUri(), mapper);
    Assertions.assertFalse(jwks.getKeys().isEmpty());
  }

  @Test
  @Order(20)
  void issuerToken(WireMockRuntimeInfo wmri) throws IOException, GeneralJwtException {
    setupWellknown(wmri);

    String issuer = wmri.getHttpsBaseUrl();
    String token = connectProvider.createJwt(issuer, "audience", "subject");
    JwtClaims claims = Assertions.assertDoesNotThrow(() -> relyingParty.verify(token));
    Assertions.assertEquals(issuer, claims.getIssuer());
    Assertions.assertEquals("subject", claims.getSubject());
    Assertions.assertEquals(List.of("audience"), claims.getAudience());
  }
}
