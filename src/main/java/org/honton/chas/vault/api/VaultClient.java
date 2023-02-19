package org.honton.chas.vault.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

@RequiredArgsConstructor
@EqualsAndHashCode
class VaultClient implements VaultApi {

  private static final String CONTENT_TYPE = "Content-Type";
  private static final String APPLICATION_JSON = "application/json";
  private static final String AUTHORIZATION = "Authorization";
  private static final String BEARER = "Bearer ";

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().findAndRegisterModules();
  private static final HttpClient HTTP_CLIENT =
      HttpClient.newBuilder()
          .version(HttpClient.Version.HTTP_2)
          .connectTimeout(Duration.ofSeconds(10))
          .build();

  private final String vaultAddress;
  private final String vaultToken;

  private static BodyPublisher getBodyPublisher(Object request) throws JsonProcessingException {
    return HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(request));
  }

  private static String base64Encode(byte[] predigested) {
    return new String(Base64.getMimeEncoder().encode(predigested), StandardCharsets.ISO_8859_1);
  }

  private static byte[] base64Decode(String substring) {
    return Base64.getMimeDecoder().decode(substring);
  }

  private <T> T send(Builder builder, String url, String... pathSegments)
      throws IOException, InterruptedException {
    URI uri = URI.create(vaultAddress + url);
    HttpResponse<String> response =
        HTTP_CLIENT.send(
            builder
                .uri(uri)
                .header(CONTENT_TYPE, APPLICATION_JSON)
                .header(AUTHORIZATION, BEARER + vaultToken)
                .build(),
            HttpResponse.BodyHandlers.ofString());
    if (200 > response.statusCode() || response.statusCode() > 300) {
      throw new IOException(response.statusCode() + " : " + response.body());
    }
    String body = response.body();
    if (body.isEmpty()) {
      return null;
    }
    Object result = OBJECT_MAPPER.readValue(body, Map.class);
    return VaultApi.walkPath(result, pathSegments);
  }

  @SneakyThrows
  private <T> T get(String url, String... pathSegments) {
    return send(HttpRequest.newBuilder().GET(), url, pathSegments);
  }

  @SneakyThrows
  private <T> T list(String url, String... pathSegments) {
    return send(HttpRequest.newBuilder().method("LIST", null), url, pathSegments);
  }

  @SneakyThrows
  private <T> T post(String url, Object request, String... pathSegments) {
    return send(HttpRequest.newBuilder().POST(getBodyPublisher(request)), url, pathSegments);
  }

  @Override
  public List<String> listKeys() {
    return list("/v1/transit/keys", "data", "keys");
  }

  @Override
  public void createKey(String name, String keyType, String autoRotationPeriod) {
    post("/v1/transit/keys/" + name, Map.of("type", keyType, "duration", autoRotationPeriod));
  }

  @Override
  public Map<String, Object> readKey(String name) {
    return get("/v1/transit/keys/" + name, "data");
  }

  @Override
  public byte[] signData(
      String name, int version, String signatureAlgorithm, String hashAlgorithm, byte[] prehashed) {
    String input = base64Encode(prehashed);
    Map<String, Serializable> body =
        signatureAlgorithm != null
            ? Map.of("input", input, "prehased", true, "signature_algorithm", signatureAlgorithm)
            : Map.of("input", input, "prehased", true);
    String signature =
        post("/v1/transit/sign/" + name + "/" + hashAlgorithm, body, "data", "signature");
    return base64Decode(signature.substring(signature.lastIndexOf(':')));
  }

  @Override
  public boolean verifySignedData(
      String name,
      int version,
      String sa,
      String hashAlgorithm,
      byte[] prehashed,
      byte[] signature) {

    String in = base64Encode(prehashed);
    String vs = "vault:v" + version + ":" + base64Encode(signature);
    Map<String, Serializable> body =
        sa != null
            ? Map.of("input", in, "prehased", true, "signature", vs, "signature_algorithm", sa)
            : Map.of("input", in, "prehased", true, "signature", vs);
    return post("/v1/transit/verify/" + name + "/" + hashAlgorithm, body, "data", "valid");
  }
}
