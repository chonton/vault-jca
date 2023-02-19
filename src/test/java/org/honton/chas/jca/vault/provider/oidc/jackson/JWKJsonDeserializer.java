package org.honton.chas.jca.vault.provider.oidc.jackson;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import java.io.IOException;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.lang.JoseException;

public class JWKJsonDeserializer extends StdDeserializer<JsonWebKey> {
  public JWKJsonDeserializer() {
    super(JsonWebKey.class);
  }

  @Override
  public JsonWebKey deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
    try {
      Map<String,Object> params = jsonParser.readValueAs(new TypeReference<Map<String, Object>>(){});
      return JsonWebKey.Factory.newJwk(params);
    } catch (JoseException e) {
      throw new JsonParseException(jsonParser, "Unable to parse Json Web Key");
    }
  }
}