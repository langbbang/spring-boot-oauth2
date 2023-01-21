package me.songha.tutorial.api.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class IndexController {

    @GetMapping("/")
    public ModelAndView index(ModelAndView modelAndView) {
        modelAndView.setViewName("index");
        return modelAndView;
    }

    @GetMapping("/view/{viewName}")
    public ModelAndView view(ModelAndView modelAndView, @PathVariable String viewName) {
        modelAndView.setViewName(viewName);
        return modelAndView;
    }

}
