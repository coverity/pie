package com.coverity.pie.core;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;

import com.coverity.pie.util.IOUtil;

public abstract class Policy {
    protected final static class FactTreeNode {
        private final String value;
        private final Collection<FactTreeNode> children;
        
        public FactTreeNode(String value) {
            this.value = value;
            this.children = new ArrayList<FactTreeNode>();
        }
    }
    
    private FactTreeNode policyRoot = new FactTreeNode(null);
    private ViolationStore violationStore = new ViolationStore();
    
    public abstract String getName();
    public abstract FactMetaData getRootFactMetaData();
    
    protected final boolean implies(String ... facts) {
        int factIndex = 0;
        FactTreeNode node = policyRoot;
        FactMetaData factMetaData = getRootFactMetaData();
        
        while (factIndex < facts.length) {
            String fact = facts[factIndex];
            FactTreeNode childNode = null;
            for (FactTreeNode child : node.children) {
                if (factMetaData.matches(child.value, fact)) {
                    childNode = child;
                    break;
                }
            }
            if (childNode == null) {
                return false;
            }
            
            factIndex += 1;
            node = childNode;
            factMetaData = factMetaData.getChildFactMetaData(node.value);
        }
        return true;
    }
    
    protected final Collection<String[]> getGrants(String ... facts) {
        Collection<String[]> grants = new ArrayList<String[]>();
        appendGrants(facts, 0, new String[facts.length], policyRoot, getRootFactMetaData(), grants);
        return grants;
    }
    
    private static void appendGrants(String[] facts, int factIndex, String[] grantArr,
            FactTreeNode root, FactMetaData rootMetaData, Collection<String[]> grants) {
        
        if (root.children.size() == 0) {
            // Add this grant if all the facts from here are NULL
            for (int i = factIndex; i < facts.length; i++) {
                if (facts[i] != null) {
                    return;
                }
                grantArr[i] = null;
            }
            grants.add(Arrays.copyOf(grantArr, grantArr.length));
            return;
        }
        
        String fact = facts[factIndex];
        for (FactTreeNode child : root.children) {
            if (fact == null || rootMetaData.matches(child.value, fact)) {
                grantArr[factIndex] = child.value;
                if (factIndex == facts.length-1) {
                    grants.add(Arrays.copyOf(grantArr, grantArr.length));
                } else {
                    appendGrants(facts, factIndex+1, grantArr, child, rootMetaData.getChildFactMetaData(child.value), grants);
                }
            }
        }
    }
    
    public void addViolationsToPolicy() {
        final String[][] violations;
        synchronized(violationStore) {
            violations = violationStore.getViolations();
            violationStore.clear();
        }
        
        for (String[] violation : violations) {
            addGrant(violation);
        }
    }
    
    protected final void addGrant(String ... facts) {
        FactTreeNode node = policyRoot;
        FactMetaData metaData = getRootFactMetaData();
        
        for (int i = 0; i < facts.length; i++) {
            FactTreeNode targetChild = null;
            FactMetaData targetMetaData = null;
            
            for (FactTreeNode child : node.children) {
                if (metaData.matches(child.value, facts[i])) {
                    targetChild = child;
                    targetMetaData = metaData.getChildFactMetaData(child.value);
                    break;
                }
            }
            if (targetChild == null) {
                targetChild = new FactTreeNode(facts[i]);
                targetMetaData = metaData.getChildFactMetaData(facts[i]);
                node.children.add(targetChild);
            }
            node = targetChild;
            metaData = targetMetaData;
        }
    }
    
    public void collapsePolicy() {
         FactTreeNode root = collapseFactTreeNode(policyRoot.value, policyRoot.children, getRootFactMetaData());
         policyRoot = root;
    }
    
    private FactTreeNode collapseFactTreeNode(String rootValue, Collection<FactTreeNode> children, FactMetaData factMetaData) {
        if (children.size() == 0) {
            return new FactTreeNode(rootValue);
        }
        
        Map<String, Collection<FactTreeNode>> childMap = new HashMap<String, Collection<FactTreeNode>>(children.size());
        for (FactTreeNode child : children) {
            if (!childMap.containsKey(child.value)) {
                childMap.put(child.value, new ArrayList<FactTreeNode>(child.children));
            } else {
                childMap.get(child.value).addAll(child.children);
            }
        }
        childMap = factMetaData.getCollapser().collapse(childMap);
        
        FactTreeNode factTreeNode = new FactTreeNode(rootValue);
        for (Map.Entry<String, Collection<FactTreeNode>> entry : childMap.entrySet()) {
            factTreeNode.children.add(collapseFactTreeNode(
                    entry.getKey(), entry.getValue(), factMetaData.getChildFactMetaData(entry.getKey())));
        }
        return factTreeNode;
    }
    
    
    public void parsePolicy(Reader reader) throws IOException {
        policyRoot = asFactTreeNode(null, new JSONObject(IOUtil.toString(reader)));
    }
    private static FactTreeNode asFactTreeNode(String value, JSONObject jsonObject) {
        FactTreeNode node = new FactTreeNode(value);
        for (Object keyObj : jsonObject.keySet()) {
            final String key = (String)keyObj;
            node.children.add(asFactTreeNode(key, jsonObject.getJSONObject(key)));
        }
        return node;
    }
    
    public void writePolicy(Writer writer) throws IOException {
        writer.write("{\n");
        writePolicy(writer, policyRoot, 1);
        writer.write("}\n");
        writer.close();
    }
    private void writePolicy(Writer writer, FactTreeNode factTreeNode, int indent) throws IOException {
        List<FactTreeNode> children = new ArrayList<FactTreeNode>(factTreeNode.children);
        Collections.sort(children, new Comparator<FactTreeNode>() {

            @Override
            public int compare(FactTreeNode o1, FactTreeNode o2) {
                if (o1.value == null) {
                    if (o2.value != null) {
                        return 1;
                    }
                    if (o2.value == null) {
                        return 0;
                    }
                    return -1;
                }
                if (o2.value == null) {
                    return 1;
                }
                return o1.value.compareTo(o2.value);
            }
            
        });
        
        for (int i = 0; i < children.size(); i++) {
            FactTreeNode child = children.get(i);
            for (int j = 0; j < indent; j++) {
                writer.write("   ");
            }
            writer.write("\"");
            writer.write(child.value.replaceAll("\\\\", "\\\\").replaceAll("\"", "\\\""));
            writer.write("\": {");
            if (child.children.size() == 0) {
                writer.write ("}");
            } else {
                writer.write("\n");
                writePolicy(writer, child, indent+1);
                for (int j = 0; j < indent; j++) {
                    writer.write("   ");
                }
                writer.write ("}");
            }
            
            if (i < children.size()-1) {
                writer.write(",");
            }
            writer.write("\n");
        }
    }
    
    protected final void logViolation(String ... facts) {
        synchronized (violationStore) {
            violationStore.logViolation(facts);
        }
    }
    
    public String[][] getViolations() {
        synchronized (violationStore) {
            return violationStore.getViolations();
        }
    }
    
    public String[][] getViolations(long sinceTime) {
        synchronized (violationStore) {
            return violationStore.getViolations(sinceTime);
        }
    }
}
