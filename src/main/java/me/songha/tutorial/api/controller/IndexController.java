package me.songha.tutorial.api.controller;

import me.songha.tutorial.utils.CookieUtil;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class IndexController {

    @GetMapping("/")
    public ModelAndView index(ModelAndView modelAndView) {
        modelAndView.setViewName("index");
        CookieUtil.addCookie();
        return modelAndView;
    }

    @GetMapping("/view/{viewName}")
    public ModelAndView view(ModelAndView modelAndView, @PathVariable String viewName) {
        modelAndView.setViewName(viewName);
        return modelAndView;
    }

    @GetMapping("/login/oauth2/code/kakao")
    public ModelAndView login(ModelAndView modelAndView, String code) {
        modelAndView.setViewName("user");
        return modelAndView;
    }

}
