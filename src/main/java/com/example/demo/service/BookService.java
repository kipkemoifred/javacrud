package com.example.demo.service;

import com.example.demo.entity.Book;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
public interface BookService {
    List<Book> getAllBooks();
    Book getBookById(Long id);
    Book createBook(Book book);
    Book updateBook(Long id, Book book);
    void deleteBook(Long id);
}

