package com.coverity.pie.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
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
    
    private final Map<Violation, Long> violationTimes = new HashMap<>();
    
    public void logViolation(String ... facts) {
        violationTimes.put(new Violation(facts), System.currentTimeMillis());
    }
    
    public String[][] getViolations() {
        String[][] violations = new String[violationTimes.size()][];
        int index = 0;
        for (Violation violation : violationTimes.keySet()) {
            violations[index++] = violation.facts;
        }
        
        return violations;
    }
    
    public String[][] getViolations(long sinceTime) {
        List<String[]> violations = new ArrayList<String[]>(violationTimes.size());
        for (Map.Entry<Violation, Long> entry : violationTimes.entrySet()) {
            if (entry.getValue() >= sinceTime) {
                violations.add(entry.getKey().facts);
            }
        }
        return violations.toArray(new String[violations.size()][]);
    }
    
    public void clear() {
        violationTimes.clear();
    }
}
