package io.github.andersori.auth.domain.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import java.net.InetAddress;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class JWTServiceImpl implements JWTService {

  private final JWKSetService jwkSetService;

  @Override
  public Mono<String> generate(String kid) {
    return jwkSetService
        .getKey(kid)
        .map(
            pair ->
                new RSAKeyProvider() {
                  @Override
                  public RSAPublicKey getPublicKeyById(String s) {
                    return (RSAPublicKey) pair.getRight();
                  }

                  @Override
                  public RSAPrivateKey getPrivateKey() {
                    return (RSAPrivateKey) pair.getLeft();
                  }

                  @Override
                  public String getPrivateKeyId() {
                    return kid;
                  }
                })
        .map(
            keyProvider ->
                JWT.create()
                    .withIssuer("https://" + InetAddress.getLoopbackAddress().getHostName())
                    .withExpiresAt(
                        Date.from(LocalDateTime.now().plusMinutes(10).toInstant(ZoneOffset.UTC)))
                    .withKeyId(kid)
                    .sign(Algorithm.RSA256(keyProvider)));
  }
}
