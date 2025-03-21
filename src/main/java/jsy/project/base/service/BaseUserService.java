package jsy.project.base.service;

import jsy.project.base.dto.request.BaseUserDto;
import jsy.project.base.entity.BaseUser;
import jsy.project.base.repository.BaseUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class BaseUserService {

    private final BaseUserRepository repository;
    private final PasswordEncoder passwordEncoder;

    public BaseUser getUser(String username) {
        return repository.findByUsername(username);
    }

    public void createNewUser(BaseUserDto userDto) {
        final String encode = passwordEncoder.encode(userDto.getPassword());
        Boolean isExist = repository.existsByUsername(userDto.getUsername());

        if(isExist) {
            return;
        }

        BaseUser baseUser = new BaseUser(userDto.getUsername(), encode, userDto.getType());
        repository.save(baseUser);
    }

}
