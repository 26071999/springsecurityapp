package com.prakash.springsecurityapp;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeResource {
    @GetMapping("/")
    public String welcome(){
        return ("<h1>Welcome to Your Page</h1");
    }

    @GetMapping("/user")
    public String user(){
        System.out.println("HI hello everyone");
        return "<h1>Welcome User</h1>";
    }

    @GetMapping("/admin")
    public String admin(){
        return "<h1>Welcome admin</h1>";
    }
}
