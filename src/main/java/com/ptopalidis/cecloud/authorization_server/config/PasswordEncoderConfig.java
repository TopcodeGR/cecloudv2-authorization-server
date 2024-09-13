package com.ptopalidis.cecloud.authorization_server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class PasswordEncoderConfig {



    @Bean
    public PasswordEncoder passwordEncoder(@Value("#{${custom.password.encoders}}")List<String> encoders,
                                           @Value("#{${custom.password.idless.encoder}}") String idlessEncoderName){



        Map<String, PasswordEncoder > encodersMapping = new HashMap<>();

        if(encoders.contains("bcrypt")){
            encodersMapping.put("bcrypt", new BCryptPasswordEncoder());
        }

        DelegatingPasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(encoders.get(0), encodersMapping);

        passwordEncoder.setDefaultPasswordEncoderForMatches(getEncoderForIdlessHash(idlessEncoderName));
        return passwordEncoder;
    }

    private PasswordEncoder getEncoderForIdlessHash(String encoderName){
        return new BCryptPasswordEncoder();
    }
}