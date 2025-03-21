package jsy.project.base.service;

import jsy.project.base.dto.response.BaseUserToken;
import jsy.project.base.entity.BaseUser;
import jsy.project.base.repository.BaseUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class BaseUserDetailService implements UserDetailsService {

    private final BaseUserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        BaseUser user = userRepository.findByUsername(username);

        if(user != null) {
            return new BaseUserToken(user);
        }
        return null;
    }
}
