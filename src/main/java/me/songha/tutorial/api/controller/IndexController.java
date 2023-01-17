package me.songha.tutorial.api.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
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
