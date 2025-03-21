package jsy.project.base.controller;


import jsy.project.base.dto.request.BaseUserDto;
import jsy.project.base.service.BaseUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/authentications")
public class AuthenticationController {

    private final BaseUserService userService;


    @PostMapping("/join")
    public String createNewUser(@RequestBody BaseUserDto userDto) {
        userService.createNewUser(userDto);
        return "ok";
    }
}
