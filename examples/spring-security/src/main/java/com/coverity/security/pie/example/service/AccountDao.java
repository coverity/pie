package com.coverity.security.pie.example.service;

import java.util.List;

import com.coverity.security.pie.example.model.Account;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AccountDao extends AbstractDao {
    public Account getAccount(String username) {
        List<?> result = getEntityManager()
            .createQuery("SELECT A FROM Account A WHERE A.user.username = :username")
            .setParameter("username", username)
            .getResultList();
        
        if (result.size() == 0) {
            return null;
        }
        return (Account)result.get(0);
    }
    
    @Transactional
    public void addAccount(Account account) {
        getEntityManager().persist(account);
    }
}
