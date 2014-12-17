package com.coverity.pie.policy.securitymanager;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.coverity.pie.core.StringCollapser;
import com.coverity.pie.util.StringUtil;

public class CsvActionCollapser implements StringCollapser {

    private static final CsvActionCollapser instance = new CsvActionCollapser();
    
    private CsvActionCollapser() {
    }
    
    public static CsvActionCollapser getInstance() {
        return instance;
    }
    
    @Override
    public <T> Map<String, Collection<T>> collapse(Map<String, Collection<T>> input) {
        List<String> actions = new ArrayList<String>();
        for (String key : input.keySet()) {
            String[] keyActions = key.split(",");
            for (String action : keyActions) {
                if (!actions.contains(action)) {
                    actions.add(action);
                }
            }
        }
        Collections.sort(actions);
        String newActions = StringUtil.join(",", actions);
        
        Collection<T> outputCol = new ArrayList<T>();
        for (Collection<T> value : input.values()) {
            outputCol.addAll(value);
        }
        return Collections.singletonMap(newActions, outputCol);
    }

}
