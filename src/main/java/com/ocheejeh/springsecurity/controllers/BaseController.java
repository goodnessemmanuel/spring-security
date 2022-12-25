package com.ocheejeh.springsecurity.controllers;


import com.ocheejeh.springsecurity.model.Book;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/")
public class BaseController {
    private final Logger LOG = LoggerFactory.getLogger(BaseController.class);


    @GetMapping("ignore")
    public ResponseEntity<String> test(){
        return ResponseEntity.of(Optional.of("null"));
    }


    @GetMapping("ignore/1")
    public ResponseEntity<String> test2(){
        return ResponseEntity.of(Optional.of("ignore 1"));
    }


    @GetMapping("books")
    public ResponseEntity<List<Book>> getBooks(){
        LOG.info(">>>Retrieving books for url {}", "/books");
        return ResponseEntity.of(
                java.util.Optional.of(List.of(
                        new Book(1L, "book 1"),
                        new Book(2L, "book 2"),
                        new Book(3L, "book 3")
                ))
        );
    }

}
