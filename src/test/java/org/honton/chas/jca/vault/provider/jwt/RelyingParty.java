package org.honton.chas.jca.vault.provider.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.util.List;
import org.jose4j.http.Get;
import org.jose4j.http.SimpleGet;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.GeneralJwtException;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;

public class RelyingParty {

  private final ObjectMapper mapper;
  private final HttpClient client;

  public RelyingParty() throws GeneralSecurityException {
    mapper = new ObjectMapper();
    client = ClientFactory.createClient();
  }

  private static AlgorithmConstraints getAlgorithmConstraints(List<String> supportedAlgorithms) {
    String[] supported = supportedAlgorithms.toArray(new String[0]);
    return new AlgorithmConstraints(ConstraintType.PERMIT, supported);
  }

  /**
   * Verify a JWT
   *
   * @param token The jwt from Authorization
   */
  public JwtClaims verify(String token)
      throws GeneralJwtException, InvalidJwtException, GeneralSecurityException {
    JwtConsumer cracker =
        new JwtConsumerBuilder()
            .setSkipAllValidators()
            .setDisableRequireSignature()
            .setSkipSignatureVerification()
            .build();

    JwtContext jwtContext = cracker.process(token);
    JwtClaims claims = jwtContext.getJwtClaims();
    verify(claims.getIssuer(), jwtContext);
    return claims;
  }
  /**
   * Verify that the JWT was issued by the specified issuer. Use the issuerUrl to fetch the jwks
   * from the OIDC well-known configuration. Use the jwks to verify the signing of the JWT.
   *
   * @param issuer The JWT issuer
   * @param jwtContext The already cracked open JWT contents
   * @throws InvalidJwtException
   */
  public void verify(String issuer, JwtContext jwtContext)
      throws InvalidJwtException, GeneralSecurityException {

    OidcWellKnown.Configuration configuration =
        OidcWellKnown.getConfiguration(client, issuer, mapper);

    // In a production system cache the JwtConsumerBuilder based upon the issuer
    HttpsJwks httpsJkws = new HttpsJwks(configuration.getJwksUri());
    Get simpleGet = new Get();
    simpleGet.setSslSocketFactory(ClientFactory.createSslSocketFactory());
    simpleGet.setHostnameVerifier(ClientFactory.createHostnameVerifier());
    httpsJkws.setSimpleHttpGet(simpleGet);

    JwtConsumerBuilder consumerBuilder =
        new JwtConsumerBuilder()
            .setSkipDefaultAudienceValidation()
            .setExpectedIssuer(issuer)
            .setVerificationKeyResolver(
                new HttpsJwksVerificationKeyResolver(httpsJkws))
            .setRequireExpirationTime()
            .setRequireSubject()
            .setJwsAlgorithmConstraints(
                getAlgorithmConstraints(configuration.getIdTokenSigningAlgValuesSupported()));

    consumerBuilder.build().processContext(jwtContext);
  }
}
