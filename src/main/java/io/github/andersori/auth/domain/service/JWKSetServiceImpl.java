package io.github.andersori.auth.domain.service;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.SequenceInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.MalformedInputException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.stream.Collectors;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class JWKSetServiceImpl implements JWKSetService {

  private final KeyFactory KEY_FACTORY = KeyFactory.getInstance("RSA");

  public JWKSetServiceImpl() throws NoSuchAlgorithmException {}

  @Override
  public Mono<String> getJWKSet() {
    return Mono.fromCallable(() -> new ClassPathResource("/key"))
        .flatMap(resource -> Mono.fromCallable(() -> new File(resource.getURI())))
        .flatMapMany(
            files -> {
              if (files.listFiles() == null) {
                return Flux.empty();
              }
              return Flux.fromArray(
                  Objects.requireNonNull(
                      files.listFiles(
                          (file) ->
                              file.isFile()
                                  && Set.of("pem", "key", "der")
                                      .contains(
                                          com.google.common.io.Files.getFileExtension(
                                              file.getName())))));
            })
        .flatMap(
            file ->
                /*First try -> PEM key on PKCS8 format*/
                Mono.fromCallable(() -> Files.readString(file.toPath(), Charset.defaultCharset()))
                    .map(
                        content ->
                            content
                                .replace("-----BEGIN PRIVATE KEY-----", "")
                                .replaceAll(System.lineSeparator(), "")
                                .replace("-----END PRIVATE KEY-----", ""))
                    .map(privateKey -> ByteBuffer.wrap(Base64.getDecoder().decode(privateKey)))
                    /*Second try -> DER key*/
                    /** MalformedInputException.class IllegalArgumentException.class */
                    .onErrorResume(
                        ex ->
                            Mono.fromCallable(
                                    () -> ByteBuffer.wrap(Files.readAllBytes(file.toPath())))
                                /*In case of an error with this file, ignore them*/
                                .onErrorResume(ex1 -> Mono.empty()))
                    .map(byteBuffer -> new PKCS8EncodedKeySpec(byteBuffer.array()))
                    .flatMap(
                        privateSpec ->
                            Mono.fromCallable(() -> KEY_FACTORY.generatePrivate(privateSpec))
                                .onErrorResume(ex -> Mono.empty()))
                    /*Private key*/
                    .flatMap(
                        privateKey ->
                            Mono.just((RSAPrivateCrtKey) privateKey)
                                .flatMap(
                                    rsaPrivateKey ->
                                        Mono.fromCallable(
                                            () ->
                                                KEY_FACTORY.generatePublic(
                                                    new RSAPublicKeySpec(
                                                        rsaPrivateKey.getModulus(),
                                                        rsaPrivateKey.getPublicExponent()))))
                                /*Public key*/
                                .map(
                                    publicKey ->
                                        new RSAKey.Builder((RSAPublicKey) publicKey)
                                            .privateKey(privateKey)
                                            .keyUse(KeyUse.SIGNATURE)
                                            .keyID(
                                                com.google.common.io.Files.getNameWithoutExtension(
                                                    file.getName()))
                                            .build()))
                    .map(JWK::toJSONString))
        .reduce("[", (a, b) -> a.equals("[") ? a + b : a + "," + b)
        .map(response -> response + "]");
  }

  @Override
  public Mono<Void> pushJWK(FilePart file) {
    if (file == null) {
      return Mono.empty();
    }
    return file.content()
        .map(DataBuffer::asInputStream)
        .reduce(SequenceInputStream::new)
        .flatMap(
            inputStream ->
                Mono.just(new ClassPathResource("/key"))
                    .flatMap(
                        classPathResource ->
                            Mono.fromCallable(() -> new File(classPathResource.getURI()))
                                .flatMap(
                                    fileDir ->
                                        Mono.fromCallable(
                                                () -> {
                                                  String newPrivateKeyName =
                                                      UUID.randomUUID().toString();
                                                  List<String> filesSystem =
                                                      Arrays.stream(
                                                              Objects.requireNonNull(
                                                                  fileDir.listFiles(File::isFile)))
                                                          .map(File::getName)
                                                          .collect(Collectors.toList());
                                                  for (int i = 0; i < filesSystem.size(); i++) {
                                                    if (newPrivateKeyName.equals(
                                                        filesSystem.get(i))) {
                                                      newPrivateKeyName =
                                                          UUID.randomUUID().toString();
                                                      i = 0;
                                                    }
                                                  }
                                                  return newPrivateKeyName;
                                                })
                                            .flatMap(
                                                fileName -> {
                                                  try {
                                                    FileOutputStream out =
                                                        new FileOutputStream(
                                                            new File(
                                                                fileDir,
                                                                fileName
                                                                    + "."
                                                                    + com.google.common.io.Files
                                                                        .getFileExtension(
                                                                            file.filename())));

                                                    String content =
                                                        new String(inputStream.readAllBytes());
                                                    if (content.contains(
                                                        "-----BEGIN PRIVATE KEY-----")) {
                                                      out.write(content.getBytes());
                                                    } else if (content.contains(
                                                        "-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
                                                      return Mono.error(
                                                          new IllegalArgumentException(
                                                              "Please, do not provide an encrypted key"));
                                                    } else {
                                                      return Mono.error(
                                                          new IllegalArgumentException(
                                                              "Please, provide key in PKCS8 format"));
                                                    }

                                                    return Mono.empty();
                                                  } catch (IOException e) {
                                                    return Mono.error(e);
                                                  }
                                                }))))
        .then();
  }

  @Override
  public Mono<Pair<PrivateKey, PublicKey>> getKey(String kid) {
    return Mono.fromCallable(() -> new ClassPathResource("/key"))
        .flatMap(resource -> Mono.fromCallable(() -> new File(resource.getURI())))
        .flatMap(
            files -> {
              if (files.listFiles() == null) {
                return Mono.empty();
              }
              return Mono.justOrEmpty(
                  Arrays.stream(
                          Objects.requireNonNull(
                              files.listFiles(
                                  (file) -> file.isFile() && file.getName().contains(kid))))
                      .findFirst());
            })
        .flatMap(
            file -> /*First try -> PEM key*/
                Mono.fromCallable(() -> Files.readString(file.toPath(), Charset.defaultCharset()))
                    .map(
                        content ->
                            content
                                .replace("-----BEGIN PRIVATE KEY-----", "")
                                .replaceAll(System.lineSeparator(), "")
                                .replace("-----END PRIVATE KEY-----", ""))
                    .map(privateKey -> ByteBuffer.wrap(Base64.getDecoder().decode(privateKey)))
                    /*Second try -> DER key*/
                    .onErrorResume(
                        MalformedInputException.class,
                        ex ->
                            Mono.fromCallable(
                                    () -> ByteBuffer.wrap(Files.readAllBytes(file.toPath())))
                                /*In case of an error with this file, ignore them*/
                                .onErrorResume(ex1 -> Mono.empty()))
                    .map(byteBuffer -> new PKCS8EncodedKeySpec(byteBuffer.array()))
                    .flatMap(
                        privateSpec ->
                            Mono.fromCallable(() -> KEY_FACTORY.generatePrivate(privateSpec))
                                .onErrorResume(ex -> Mono.empty())))
        .flatMap(
            privateKey ->
                Mono.just((RSAPrivateCrtKey) privateKey)
                    .flatMap(
                        rsaPrivateKey ->
                            Mono.fromCallable(
                                () ->
                                    KEY_FACTORY.generatePublic(
                                        new RSAPublicKeySpec(
                                            rsaPrivateKey.getModulus(),
                                            rsaPrivateKey.getPublicExponent()))))
                    .map(publicKey -> Pair.of(privateKey, publicKey)));
  }
}
