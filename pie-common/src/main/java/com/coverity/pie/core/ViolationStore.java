package com.coverity.pie.core;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class ViolationStore {
    private static class Violation {
        private final String[] facts;

        public Violation(String[] facts) {
            super();
            this.facts = facts;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + Arrays.hashCode(facts);
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            Violation other = (Violation) obj;
            if (!Arrays.equals(facts, other.facts))
                return false;
            return true;
        }
        
    }
    
    private final Map<Violation, Long> violationCount = new HashMap<>();
    
    public void logViolation(String ... facts) {
        Violation violation = new Violation(facts);
        Long count = violationCount.get(violation);
        if (count == null) {
            violationCount.put(violation, 1L);
        } else {
            violationCount.put(violation, count+1L);
        }
    }
    
    public String[][] getViolations() {
        String[][] violations = new String[violationCount.size()][];
        int index = 0;
        for (Violation violation : violationCount.keySet()) {
            violations[index++] = violation.facts;
        }
        
        return violations;
    }
    
    public void clear() {
        violationCount.clear();
    }
}
