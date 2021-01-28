package io.github.andersori.auth.domain.service;

import java.security.PrivateKey;
import java.security.PublicKey;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.http.codec.multipart.FilePart;
import reactor.core.publisher.Mono;

public interface JWKSetService {
  Mono<String> getJWKSet();

  Mono<Void> pushJWK(FilePart file);

  Mono<Pair<PrivateKey, PublicKey>> getKey(String kid);
}
