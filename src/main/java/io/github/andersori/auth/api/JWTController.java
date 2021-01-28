package io.github.andersori.auth.api;

import io.github.andersori.auth.domain.service.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/jwt")
@RequiredArgsConstructor
public class JWTController {

  private final JWTService service;

  @GetMapping(produces = MediaType.TEXT_PLAIN_VALUE)
  Mono<String> generate(String kid) {
    return service.generate(kid);
  }
}
