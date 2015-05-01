package com.coverity.security.pie.policy.securitymanager.fact;

import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;

import com.coverity.security.pie.core.FactMetaData;
import com.coverity.security.pie.core.NullStringCollapser;
import com.coverity.security.pie.core.PolicyConfig;
import com.coverity.security.pie.core.StringCollapser;

public class JmxMBeanObjectNameFactMetaData implements FactMetaData {

    private static final JmxMBeanObjectNameFactMetaData instance = new JmxMBeanObjectNameFactMetaData();
    
    private JmxMBeanObjectNameFactMetaData() {
    }
    
    public static JmxMBeanObjectNameFactMetaData getInstance() {
        return instance;
    }
    
    @Override
    public StringCollapser getCollapser(PolicyConfig policyConfig) {
        // FIXME: ObjectName spec is quite general, so deciding how to collapse is non-trivial
        return NullStringCollapser.getInstance();
    }

    @Override
    public boolean matches(String matcher, String matchee) {
        try {
            return new ObjectName(matcher).apply(new ObjectName(matchee));
        } catch (MalformedObjectNameException e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public FactMetaData getChildFactMetaData(String fact) {
        return PermissionActionFactMetaData.getInstance();
    }

}
