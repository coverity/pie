package com.coverity.security.pie.example.service;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.springframework.security.access.annotation.Secured;

@Secured({"PIE"})
public abstract class AbstractDao {

    @PersistenceContext
    private EntityManager entityManager;
    
    protected EntityManager getEntityManager() {
        return entityManager;
    }
    
    public static <T> List<T> castList(List<?> list, Class<T> clazz) {
        if (list == null) {
            return null;
        }
        List<T> output = new ArrayList<T>(list.size());
        for (Object obj : list) {
            output.add(clazz.cast(obj));
        }
        return output;
    }

}
