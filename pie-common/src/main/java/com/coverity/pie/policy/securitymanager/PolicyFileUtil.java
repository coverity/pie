package com.coverity.pie.policy.securitymanager;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.coverity.pie.policy.securitymanager.collapse.Collapser;
import com.coverity.pie.util.FileParser;
import com.coverity.pie.util.IOUtil;
import com.coverity.pie.util.StringUtil;

public class PolicyFileUtil {
    private static class Grant {
        private final String codeSource;
        private final String permissionClass;
        private final String name;
        private final String action;
        
        public Grant(String codeSource, String permissionClass, String name, String action) {
            this.codeSource = codeSource;
            this.permissionClass = permissionClass;
            this.name = name;
            this.action = action;
        }
        
        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result
                    + ((action == null) ? 0 : action.hashCode());
            result = prime * result
                    + ((codeSource == null) ? 0 : codeSource.hashCode());
            result = prime * result + ((name == null) ? 0 : name.hashCode());
            result = prime
                    * result
                    + ((permissionClass == null) ? 0 : permissionClass
                            .hashCode());
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
            Grant other = (Grant) obj;
            if (action == null) {
                if (other.action != null)
                    return false;
            } else if (!action.equals(other.action))
                return false;
            if (codeSource == null) {
                if (other.codeSource != null)
                    return false;
            } else if (!codeSource.equals(other.codeSource))
                return false;
            if (name == null) {
                if (other.name != null)
                    return false;
            } else if (!name.equals(other.name))
                return false;
            if (permissionClass == null) {
                if (other.permissionClass != null)
                    return false;
            } else if (!permissionClass.equals(other.permissionClass))
                return false;
            return true;
        }
    }
    
    private static List<Grant> parsePolicyFile(String path) {
        
        FileReader fr = null;
        
        StringBuilder sb = new StringBuilder();
        try {
            fr = new FileReader(path);
            
            final char buffer[] = new char[4096];
            int n;
            while ((n = fr.read(buffer)) > 0) {
                sb.append(buffer, 0, n);
            }
            fr.close();
        } catch (IOException e) {
            if (fr != null) {
                try {
                    fr.close();
                } catch (IOException e2) {
                    // Do nothing
                }
            }
            throw new RuntimeException(e);
        }
        
        String[] tokens = FileParser.tokenize(sb.toString(), new char[]{ ';' });
        
        List<Grant> grants = new ArrayList<Grant>();
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
                            String actionsArr[] = actions.substring(1, actions.length()-1).split(",");
                            for (String action : actionsArr) {
                                grants.add(new Grant(codeSource, permClass, name, action));        
                            }
                        } else {
                            grants.add(new Grant(codeSource, permClass, name, null));
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
        
        return grants;
    }
    
    
    
    public static void buildPolicyFile(URL path, boolean simple, Collection<PermissionRequest> permissionRequests, Collection<Collapser> collapsers) {
        if (!path.getProtocol().equals("file")) {
            throw new IllegalArgumentException("Can only write to filesystem paths.");
        }
        List<Grant> grants = new ArrayList<Grant>();
        if (new File(path.getPath()).exists()) {
            grants.addAll(parsePolicyFile(path.getPath()));
        }
        for (PermissionRequest permissionRequest : permissionRequests) {
            grants.add(new Grant(permissionRequest.getCodeSource(), permissionRequest.getPermissionClassName(),
                    permissionRequest.getPermissionName(), permissionRequest.getPermissionAction()));
        }
        
        Map<String, Map<String, Map<String, Collection<String>>>> permsByActionByTypeByClass = new HashMap<>();
        for (Grant grant : grants) {
            if (!permsByActionByTypeByClass.containsKey(grant.codeSource)) {
                permsByActionByTypeByClass.put(grant.codeSource, new HashMap<String, Map<String, Collection<String>>>());
            }
            Map<String, Map<String, Collection<String>>> permsByActionByType = permsByActionByTypeByClass.get(grant.codeSource);
            
            if (!permsByActionByType.containsKey(grant.permissionClass)) {
                permsByActionByType.put(grant.permissionClass, new HashMap<String, Collection<String>>());
            }
            Map<String, Collection<String>> permsByAction = permsByActionByType.get(grant.permissionClass);
            if (!permsByAction.containsKey(grant.action)) {
                permsByAction.put(grant.action, new HashSet<String>());
            }
            permsByAction.get(grant.action).add(grant.name);
        }
        
        if (simple) {
            Map<String, Map<String, Map<String, Collection<String>>>> simplified = new HashMap<>();
            Pattern libPattern = Pattern.compile("(.*)\\/WEB-INF\\/lib\\/");
            Pattern classesPattern = Pattern.compile("(.*)\\/WEB-INF\\/classes\\/");
            
            for (Map.Entry<String, Map<String, Map<String, Collection<String>>>> classesEntry : permsByActionByTypeByClass.entrySet()) {
                String className = classesEntry.getKey();
                Map<String, Map<String, Collection<String>>> permsByActionByType = classesEntry.getValue();
                
                Matcher m = libPattern.matcher(className);
                if (m.find()) {
                    className = m.group(1) + "/WEB-INF/lib/-";
                } else {
                    m = classesPattern.matcher(className);
                    if (m.find()) {
                        className = m.group(1) + "/WEB-INF/classes/-";
                    }
                }
                
                if (!simplified.containsKey(className)) {
                    simplified.put(className, new HashMap<String, Map<String, Collection<String>>>());
                }
                for (Map.Entry<String, Map<String, Collection<String>>> typeEntry : permsByActionByType.entrySet()) {
                    String permType = typeEntry.getKey();
                    Map<String, Collection<String>> permsByAction = typeEntry.getValue();
                    if (!simplified.get(className).containsKey(permType)) {
                        simplified.get(className).put(permType, new HashMap<String, Collection<String>>());
                    }
                    
                    for (Map.Entry<String, Collection<String>> actionEntry : permsByAction.entrySet()) {
                        String action = actionEntry.getKey();
                        if (!simplified.get(className).get(permType).containsKey(action)) {
                            simplified.get(className).get(permType).put(action, new HashSet<String>());
                        }
                        simplified.get(className).get(permType).get(action).addAll(actionEntry.getValue());
                    }
                }
            }
            
            permsByActionByTypeByClass = simplified;
        }
        
        // Do the collapse
        for (Map<String, Map<String, Collection<String>>> permsByActionByType : permsByActionByTypeByClass.values()) {
            for (Map.Entry<String, Map<String, Collection<String>>> typeEntry : permsByActionByType.entrySet()) {
                String permType = typeEntry.getKey();
                Map<String, Collection<String>> permsByAction = typeEntry.getValue();
                
                for (Map.Entry<String, Collection<String>> actionEntry : permsByAction.entrySet()) {
                    String action = actionEntry.getKey();
                    Collection<String> names = new ArrayList<String>(actionEntry.getValue());
                    
                    for (Collapser collapser : collapsers) {
                        if (collapser.supportedPermissions().contains(permType)) {
                            names = collapser.collapse(names);
                        }
                    }
                    permsByAction.put(action, names);
                }
            }
        }
        
        FileWriter fw = null;
        try {
            fw = new FileWriter(path.getPath());
            List<String> classNames = new ArrayList<String>(permsByActionByTypeByClass.keySet());
            Collections.sort(classNames);
            for (String className : classNames) {
                Map<String, Map<String, Collection<String>>> permsByActionByType = permsByActionByTypeByClass.get(className);
                
                List<String> permTypes = new ArrayList<String>(permsByActionByType.keySet());
                Collections.sort(permTypes);
                
                fw.write("grant codeBase \"" + className + "\" {\n");
                
                for (String permType : permTypes) {
                    Map<String, Collection<String>> permsByAction = permsByActionByType.get(permType);
                    
                    Map<String, Collection<String>> outPerms = new HashMap<>();
                    
                    for (Map.Entry<String, Collection<String>> actionEntry : permsByAction.entrySet()) {
                        String action = actionEntry.getKey();
                        Collection<String> names = actionEntry.getValue();
                        for (String name : names) {
                            if (!outPerms.containsKey(name)) {
                                outPerms.put(name, new HashSet<String>());
                            }
                            if (action != null) {
                                outPerms.get(name).add(action);
                            }
                        }
                    }
                    
                    List<String> names = new ArrayList<String>(outPerms.keySet());
                    Collections.sort(names);
                    
                    for (String name : names) {
                        List<String> actions = new ArrayList<String>(outPerms.get(name));
                        Collections.sort(actions);
                        
                        if (actions.size() == 0) {
                            fw.write("    permission " + permType + " \"" + name + "\";\n");
                        } else {
                            fw.write("    permission " + permType + " \"" + name + "\", \"" + StringUtil.join(",", actions) + "\";\n");
                        }
                    }
                    
                }
                fw.write("};\n");
            }
            
            fw.close();
        } catch (IOException e) {
            IOUtil.closeSilently(fw);
            throw new RuntimeException(e);
        }
        
    }
}
