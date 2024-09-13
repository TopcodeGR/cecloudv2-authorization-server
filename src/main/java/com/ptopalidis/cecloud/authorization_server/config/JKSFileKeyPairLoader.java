package com.ptopalidis.cecloud.authorization_server.config;

import org.springframework.core.io.ClassPathResource;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

public class JKSFileKeyPairLoader {


    public static KeyPair loadKeyStore(String privateKey, String password, String alias) throws  Exception{


        final KeyStore keyStore = KeyStore.getInstance("JKS");

        keyStore.load(new ClassPathResource(privateKey).getInputStream(), password.toCharArray());

        final PrivateKey key = (PrivateKey) keyStore.getKey(alias,password.toCharArray());

        final Certificate cert = keyStore.getCertificate(alias);
        final PublicKey publicKey = cert.getPublicKey();

        return new KeyPair(publicKey,key);
    }
}
