package jsy.project.base.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/boards")
public class TestController {

    @GetMapping
    public String testGet() {
        return "ok";
    }
 }
