package com.coverity.pie.policy.securitymanager.fact;

import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.PolicyConfig;
import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.core.UnsupportedFactMetaData;
import com.coverity.pie.policy.securitymanager.CsvActionCollapser;

public class CsvActionFactMetaData implements FactMetaData {

    private static final CsvActionFactMetaData instance = new CsvActionFactMetaData();
    
    private CsvActionFactMetaData() {
    }
    
    public static CsvActionFactMetaData getInstance() {
        return instance;
    }
    
    @Override
    public StringCollapser getCollapser(PolicyConfig policyConfig) {
        return CsvActionCollapser.getInstance();
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        String[] a = matcher.split(",");
        String[] b = matchee.split(",");
        for (String target : b) {
            boolean found = false;
            for (int i = 0; i < a.length; i++) {
                if (a[i].equals(target)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        return UnsupportedFactMetaData.getInstance();
    }

}
