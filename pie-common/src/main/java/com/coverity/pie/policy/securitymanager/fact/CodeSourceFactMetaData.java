package com.coverity.pie.policy.securitymanager.fact;

import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.NullStringCollapser;
import com.coverity.pie.core.StringCollapser;

public class CodeSourceFactMetaData implements FactMetaData {

    private static final CodeSourceFactMetaData instance = new CodeSourceFactMetaData();
    
    private CodeSourceFactMetaData() {
    }
    
    public static CodeSourceFactMetaData getInstance() {
        return instance;
    }
    
    @Override
    public StringCollapser getCollapser() {
        return NullStringCollapser.getInstance();
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        final String[] a = matcher.split("/");
        final String[] b = matchee.split("/");
        
        if (a[a.length-1].equals("-")) {
            if (a.length < b.length) {
                return false;
            }
            for (int i = 0; i < a.length-1; i++) {
                if (!a[i].equals(b[i])) {
                    return false;
                }
            }
            return true;
        }
        if (a[a.length-1].equals("*")) {
            if (a.length != b.length) {
                return false;
            }
            for (int i = 0; i < a.length-1; i++) {
                if (!a[i].equals(b[i])) {
                    return false;
                }
            }
            return true;
        }
        
        return matcher.equals(matchee);
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        return PermissionClassFactMetaData.getInstance();
    }

}
