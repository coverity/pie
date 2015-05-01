package com.coverity.security.pie.example.model;

import java.math.BigDecimal;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class Account {
    
    @Id @GeneratedValue
    private Long id;
    
    @ManyToOne(optional = false)
    private User user;
    
    @Column(nullable = false)
    private BigDecimal balance;

    public User getUser() {
        return user;
    }
    public void setUser(User user) {
        this.user = user;
    }
    public BigDecimal getBalance() {
        return balance;
    }
    public void setBalance(BigDecimal balance) {
        this.balance = balance;
    }
    
    
}
