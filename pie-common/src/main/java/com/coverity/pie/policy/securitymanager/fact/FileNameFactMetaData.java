package com.coverity.pie.policy.securitymanager.fact;

import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.util.collapser.FilePathCollapser;

public class FileNameFactMetaData implements FactMetaData {

    private static final FileNameFactMetaData instance = new FileNameFactMetaData();
    
    private FileNameFactMetaData() {
    }
    
    public static FileNameFactMetaData getInstance() {
        return instance;
    }
    
    private final FilePathCollapser filePathCollapser = new FilePathCollapser(0);
    
    @Override
    public StringCollapser getCollapser() {
        return filePathCollapser;
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        return filePathCollapser.pathNameMatches(matcher, matchee);
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        return CsvActionFactMetaData.getInstance();
    }

}
