package com.coverity.pie.policy.securitymanager;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.security.CodeSource;
import java.security.Permission;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.coverity.pie.core.FactMetaData;
import com.coverity.pie.core.Policy;
import com.coverity.pie.policy.securitymanager.fact.CodeSourceFactMetaData;
import com.coverity.pie.util.FileParser;
import com.coverity.pie.util.IOUtil;

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
        return super.implies(concat(toString(codeSource), getPermissionFacts(permission)));
    }
    public void logViolation(CodeSource codeSource, Permission permission) {
        super.logViolation(concat(toString(codeSource), getPermissionFacts(permission)));    
    }
    
    private static String[] concat(String a, String[] b) {
        String[] result = new String[b.length+1];
        System.arraycopy(b, 0, result, 1, b.length);
        result[0] = a;
        return result;
    }
    
    private static String[] getPermissionFacts(Permission permission) {
        if (permission instanceof javax.management.MBeanPermission) {

            String name = permission.getName(); 
            String objectName = null;
            String member = null;
            String className = null;

            int openingBracket = name.indexOf("[");
            if (openingBracket == -1) {
                objectName = "*:*";
            } else {
                if (!name.endsWith("]")) {
                    // Illegal name format, fallback to default
                    String actions = permission.getActions();
                    if (actions == null) {
                        return new String[] {
                                permission.getClass().getName(),
                                permission.getName()
                        };
                    } else {
                        return new String[] {
                                permission.getClass().getName(),
                                permission.getName(),
                                actions
                        };
                    }
                } else {
                    String on = name.substring(openingBracket + 1,
                                               name.length() - 1);
                    if (on.equals("")) {
                        objectName = "*:*";
                    } else { 
                        objectName = on;
                    }
                }

                name = name.substring(0, openingBracket);
            }

            // Parse member
            int poundSign = name.indexOf("#");
            if (poundSign == -1) {
                member = "*";
            } else {
                String memberName = name.substring(poundSign + 1);
                member = memberName;
                name = name.substring(0, poundSign);
            }

            // Parse className
            className = name;
            
            return new String[] { permission.getClass().getName(),
                    className, member, objectName, permission.getActions() }; 
        }
        
        String actions = permission.getActions();
        if (actions == null) {
            return new String[] {
                    permission.getClass().getName(),
                    permission.getName()
            };
        } else {
            return new String[] {
                    permission.getClass().getName(),
                    permission.getName(),
                    actions
            };
        }
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
        
        List<String> codeSources = new ArrayList<String>(grantsByCodeSource.keySet());
        Collections.sort(codeSources);
        
        for (String codeSource : codeSources) {
            writer.write("grant codeBase \"" + codeSource + "\" {\n");
            
            List<String[]> grants = new ArrayList<String[]>(grantsByCodeSource.get(codeSource));
            Collections.sort(grants, new Comparator<String[]>() {
                @Override
                public int compare(String[] o1, String[] o2) {
                    int c = o1[1].compareTo(o2[1]);
                    if (c != 0) {
                        return c;
                    }
                    c = o1[2].compareTo(o2[2]);
                    if (c != 0) {
                        return c;
                    }
                    if (o1.length < 4 && o2.length == 4) {
                        return -1;
                    }
                    if (o1.length == 4 && o2.length < 4) {
                        return 1;
                    }
                    if (o1[3] == null && o2[3] == null) {
                        return 0;
                    }
                    if (o1[3] == null && o2[3] != null) {
                        return -1;
                    }
                    if (o1[3] != null && o2[3] == null) {
                        return 1;
                    }
                    return o1[3].compareTo(o2[3]);
                }
            });
            
            for (String[] grant : grants) {
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
    
    public void parseJavaPolicy(Reader reader) {
        
        StringBuilder sb = new StringBuilder();
        try {
            final char buffer[] = new char[4096];
            int n;
            while ((n = reader.read(buffer)) > 0) {
                sb.append(buffer, 0, n);
            }
            reader.close();
        } catch (IOException e) {
            IOUtil.closeSilently(reader);
            throw new RuntimeException(e);
        }
        
        String[] tokens = FileParser.tokenize(sb.toString(), new char[]{ ';' });
        
        int pos = 0;
        while (pos < tokens.length) {
            int next = FileParser.nextToken("{", tokens, pos);
            if (next == -1) {
                break;
            }
            if (tokens[pos].equals("grant") && tokens[pos+1].equals("codeBase")) {
                String codeSource = tokens[pos+2];
                codeSource = codeSource.substring(1, codeSource.length()-1);
                
                pos = next+1;
                next = FileParser.nextToken(";", tokens, pos);
                while (!tokens[pos].equals("}")) {
                    if (next == -1) {
                        break;
                    }
                    if (tokens[pos].equals("permission") && next >= pos+2) {
                        String permClass = tokens[pos+1];
                        String name = tokens[pos+2];
                        
                        if (name.endsWith(",")) {
                            name = name.substring(1, name.length()-2);
                        } else {
                            name = name.substring(1, name.length()-1);
                        }
                        
                        if (next > pos+3) {
                            String actions = tokens[pos+3];
                            actions = actions.substring(1, actions.length()-1);
                            addGrant(codeSource, permClass, name, actions);
                        } else {
                            addGrant(codeSource, permClass, name);
                        }
                    }
                    
                    pos = next+1;
                    next = FileParser.nextToken(";", tokens, pos);
                }
                
                pos = next+1;
            } else {
                next = FileParser.nextToken("}", tokens, pos);
                next = FileParser.nextToken(";", tokens, next);
                pos = next+1;
            }
        }
    }
    
    private static String toString(CodeSource codeSource) {
        if (codeSource != null && codeSource.getLocation() != null) {
            return codeSource.getLocation().toString();
        } else {
            return "<null>";
        }
    }
    
}
