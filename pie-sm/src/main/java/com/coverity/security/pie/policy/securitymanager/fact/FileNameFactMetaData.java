package com.coverity.security.pie.policy.securitymanager.fact;

import java.util.HashMap;
import java.util.Map;

import com.coverity.security.pie.core.FactMetaData;
import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.core.StringCollapser;
import com.coverity.security.pie.util.collapser.FilePathCollapser;

public class FileNameFactMetaData implements FactMetaData {

    private static final FileNameFactMetaData instance = new FileNameFactMetaData();
    
    private FileNameFactMetaData() {
    }
    
    public static FileNameFactMetaData getInstance() {
        return instance;
    }
    
    private final Map<Integer, StringCollapser> collapsers = new HashMap<Integer, StringCollapser>();;
    private final FilePathCollapser defaultCollapser = new FilePathCollapser(2);
    
    @Override
    public StringCollapser getCollapser(PolicyConfig policyConfig) {
        int collapseThreshold = policyConfig.getInteger("FilePermission.collapseThreshold", 2);
        if (collapseThreshold == 2) {
            return defaultCollapser;
        }
        
        synchronized (collapsers) {
            if (collapsers.containsKey(collapseThreshold)) {
                return collapsers.get(collapseThreshold);
            }
            StringCollapser collapser = new FilePathCollapser(collapseThreshold);
            collapsers.put(collapseThreshold, collapser);
            return collapser;
        }
        
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        return defaultCollapser.pathNameMatches(matcher, matchee);
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        return CsvActionFactMetaData.getInstance();
    }

}
