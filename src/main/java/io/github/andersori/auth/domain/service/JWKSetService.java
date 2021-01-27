package io.github.andersori.auth.domain.service;

import org.springframework.http.codec.multipart.FilePart;
import reactor.core.publisher.Mono;

public interface JWKSetService {
  Mono<String> getJWKSet();

  Mono<Void> pushJWK(FilePart file);
}
