package com.coverity.pie.example.service;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.coverity.pie.example.model.User;

@Service
public class UserDao extends AbstractDao {
    
    public List<User> getUsers() {
        return castList(getEntityManager().createQuery("SELECT U FROM User U").getResultList(), User.class);
    }
    
    @Transactional
    public void addUser(User user) {
        getEntityManager().persist(user);
    }
    
}
