package com.sfiss.gateway.gateway_mvc.cache;

import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthorizationRepository {

    @CachePut(value = "autorizacoes", key = "#chave", cacheManager = "autorizacao-cache")
    public UserDetails put(String chave, Authentication authentication) {
        log.debug("Adicionando informações ao cache {}", chave);

        if (authentication.getPrincipal() instanceof UserDetails) {
            return (UserDetails) authentication.getPrincipal();
        }

        return new User(authentication.getName(), "", authentication.getAuthorities());
    }

    @Cacheable(value="autorizacoes", cacheManager = "autorizacao-cache")
    public Optional<UserDetails> get(String chave) {
        log.debug("Resgatando informações do token {}", chave);
        return Optional.empty();
    }

}

