package io.github.andersori.auth.api;

import io.github.andersori.auth.domain.service.JWKSetService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/jwk")
@RequiredArgsConstructor
public class JWKSController {

  private final JWKSetService service;

  @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
  Mono<String> getJWKSet() {
    return service.getJWKSet();
  }

  @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  Mono<Void> pushJWK(@RequestPart FilePart file) {
    return service.pushJWK(file);
  }
}
