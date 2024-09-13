package com.ptopalidis.cecloud.authorization_server.services;


import com.ptopalidis.cecloud.authorization_server.entities.User;
import com.ptopalidis.cecloud.authorization_server.model.UserDetailsEntity;
import com.ptopalidis.cecloud.authorization_server.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class JpaUserDetailsService implements UserDetailsService {


    private final UserRepository userRepository;

    public JpaUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
        Optional<User> userOptional = userRepository.findUserByUsername(username);

        if(userOptional.isPresent()){
            return new UserDetailsEntity(userOptional.get());
        }

        throw  new UsernameNotFoundException("User not found");
    }
}
