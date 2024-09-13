package com.ptopalidis.cecloud.authorization_server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.ptopalidis.cecloud.authorization_server.model.UserDetailsEntity;
import com.ptopalidis.cecloud.authorization_server.repositories.UserRepository;
import com.ptopalidis.cecloud.authorization_server.services.JpaUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Configuration
public class SecurityConfigStaticKey {


    @Value("${password}")
    private String password;

    @Value("${privateKey}")
    private  String privateKey;

    @Value("${alias}")
    private  String alias;

    @Value("${bff-client.client-id}")
    private String bffClientId;

    @Value("${bff-client.client-secret}")
    private String bffClientSecret;

    @Value("${bff-client.redirect-uri}")
    private String bffClientRedirectUri;

    @Value("${bff-client.post-logout-redirect-uri}")
    private String bffClientPostLogoutRedirectUri;


    @Bean
    public JWKSource<SecurityContext> jwkSource() throws  Exception{

        KeyPair keyPair = JKSFileKeyPairLoader.loadKeyStore(privateKey,password,alias);
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(rsaPrivateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwSet  = new JWKSet(rsaKey);

        return new ImmutableJWKSet<>(jwSet);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain asFilterChain(HttpSecurity http) throws  Exception{
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
        http.exceptionHandling((e)->e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));


        return http.build();
    }


    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws  Exception{
        http.formLogin(Customizer.withDefaults());
        http.authorizeHttpRequests(c -> c.anyRequest().authenticated());
        return http.build();
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(bffClientId)
                .clientSecret(bffClientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(bffClientRedirectUri)
                .scope(OidcScopes.OPENID)
                .postLogoutRedirectUri(bffClientPostLogoutRedirectUri)
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(12)).build())
                .build();


        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository){
        return new JpaUserDetailsService(userRepository);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        return authProvider;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(){

        return context -> {
            List<String> auths = new ArrayList<>();

            for(GrantedAuthority auth: context.getPrincipal().getAuthorities()){
                auths.add(auth.getAuthority());
            }
            JwtClaimsSet.Builder claims  = context.getClaims();
            claims.claim("authorities",auths);
            claims.claim("userId", ((UserDetailsEntity) context.getPrincipal().getPrincipal()).getUser().getId());
        };
    }

}
