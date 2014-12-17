package com.coverity.pie.policy.csp.fact;

import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.util.collapser.UriCspDirectiveCollapser;

public class UriFactMetaData implements FactMetaData {

    private static final UriFactMetaData instance = new UriFactMetaData();
    
    private UriFactMetaData() {
    }
    
    public static UriFactMetaData getInstance() {
        return instance;
    }
    
    private final UriCspDirectiveCollapser uriCspDirectiveCollapser = new UriCspDirectiveCollapser(2);
    
    @Override
    public StringCollapser getCollapser() {
        return uriCspDirectiveCollapser;
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        return uriCspDirectiveCollapser.pathNameMatches(matcher, matchee);
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        return DirectiveFactMetaData.getInstance();
    }

}
