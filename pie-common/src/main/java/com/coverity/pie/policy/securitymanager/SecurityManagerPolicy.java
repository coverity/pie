package com.coverity.pie.policy.securitymanager;

import java.io.IOException;
import java.io.Writer;
import java.security.CodeSource;
import java.security.Permission;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.Policy;
import com.coverity.pie.policy.securitymanager.fact.CodeSourceFactMetaData;

public class SecurityManagerPolicy extends Policy {

    @Override
    public String getName() {
        return "securityManager";
    }
    
    @Override
    public FactMetaData getRootFactMetaData() {
        return CodeSourceFactMetaData.getInstance();
    }
    
    public boolean implies(CodeSource codeSource, Permission permission) {
        return implies(codeSource.getLocation().toString(), permission.getClass().getName(), permission.getName(), permission.getActions());
    }
    public void logViolation(CodeSource codeSource, Permission permission) {
        super.logViolation(codeSource.getLocation().toString(), permission.getClass().getName(), permission.getName(), permission.getActions());
    }
    
    public void writeJavaPolicy(Writer writer) throws IOException {
        Collection<String[]> allGrants = getGrants(null, null, null, null);
        Map<String, Collection<String[]>> grantsByCodeSource = new HashMap<String, Collection<String[]>>();
        for (String[] grant : allGrants) {
            if (!grantsByCodeSource.containsKey(grant[0])) {
                Collection<String[]> c = new ArrayList<String[]>();
                c.add(grant);
                grantsByCodeSource.put(grant[0], c);
            } else {
                grantsByCodeSource.get(grant[0]).add(grant);
            }
        }
        
        for (Map.Entry<String, Collection<String[]>> grantByCodeSource : grantsByCodeSource.entrySet()) {
            writer.write("grant codeBase \"" + grantByCodeSource.getKey() + "\" {\n");
            
            for (String[] grant : grantByCodeSource.getValue()) {
                if (grant[3] == null) {
                    writer.write("    permission " + grant[1] + " \"" + grant[2] + "\";\n");
                } else {
                    writer.write("    permission " + grant[1] + " \"" + grant[2] + "\", \"" + grant[3] + "\";\n");
                }
            }
            writer.write("};\n");
        }
        writer.close();
    }

}
