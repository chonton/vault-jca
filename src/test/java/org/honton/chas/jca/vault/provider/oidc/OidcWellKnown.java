package org.honton.chas.jca.vault.provider.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import lombok.extern.jackson.Jacksonized;
import org.honton.chas.jca.vault.provider.oidc.jackson.JWKJsonDeserializer;
import org.honton.chas.jca.vault.provider.oidc.jackson.JWKJsonSerializer;
import org.jose4j.jwk.JsonWebKey;
import org.junit.jupiter.api.Assertions;

// @Path("/.well-known")
// @Produces(MediaType.APPLICATION_JSON)
@UtilityClass
public class OidcWellKnown {

  @SneakyThrows
  private <T> T getWellKnown(HttpClient client, String path, ObjectMapper mapper, Class<T> clss) {
    HttpRequest.Builder builder =
        HttpRequest.newBuilder()
            .GET()
            .uri(URI.create(path))
            .header("Content-Type", "application/json");

    HttpResponse<String> response =
        client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    Assertions.assertEquals(200, response.statusCode());

    return mapper.readValue(response.body(), clss);
  }

  // @Path("/openid-configuration")
  // @GET
  public Configuration getConfiguration(HttpClient client, String issuer, ObjectMapper mapper) {
    return getWellKnown(
        client, issuer + "/.well-known/openid-configuration", mapper, Configuration.class);
  }

  // @GET
  // usually @Path("/.well-known/jwks.json")
  public JsonWebKeySet getJwks(HttpClient client, String jwksUri, ObjectMapper mapper) {
    return getWellKnown(client, jwksUri, mapper, JsonWebKeySet.class);
  }

  @Data
  @Jacksonized
  @Builder
  @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
  public static class Configuration {
    String issuer;
    String jwksUri;
    String authorizationEndpoint;
    List<String> responseTypesSupported;
    List<String> subjectTypesSupported;
    List<String> idTokenSigningAlgValuesSupported;
    List<String> claimsSupported;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  public static class JsonWebKeySet {
    @JsonSerialize(contentUsing = JWKJsonSerializer.class)
    @JsonDeserialize(contentUsing = JWKJsonDeserializer.class)
    List<JsonWebKey> keys;
  }
}
