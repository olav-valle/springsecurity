package no.ovalle.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplateController {

    @GetMapping("login")
    public String getLogin() {
        // the returned String has to match a file in /src/main/resources/templates/ without extension,
        // i.e. "login"
        return "login";
    }

    @GetMapping("courses")
    public String getCourses() {
        return "courses";
    }

}
