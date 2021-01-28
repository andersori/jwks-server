package io.github.andersori.auth.domain.service;

import reactor.core.publisher.Mono;

public interface JWTService {
  Mono<String> generate(String kid);
}
