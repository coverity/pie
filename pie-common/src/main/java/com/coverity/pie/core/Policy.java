package com.coverity.pie.core;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
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
    
    private FactTreeNode policyRoot = null;
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
            FactTreeNode node = policyRoot;
            FactMetaData metaData = getRootFactMetaData();
            
            for (int i = 0; i < violation.length; i++) {
                FactTreeNode targetChild = null;
                FactMetaData targetMetaData = null;
                
                for (FactTreeNode child : node.children) {
                    if (metaData.matches(child.value, violation[i])) {
                        targetChild = child;
                        targetMetaData = metaData.getChildFactMetaData(child.value);
                        break;
                    }
                }
                if (targetChild == null) {
                    targetChild = new FactTreeNode(violation[i]);
                    targetMetaData = metaData.getChildFactMetaData(violation[i]);
                    node.children.add(targetChild);
                }
                node = targetChild;
                metaData = targetMetaData;
            }
        }
    }
    
    public void collapsePolicy() {
         FactTreeNode root = collapseFactTreeNode(policyRoot.value, policyRoot.children, getRootFactMetaData());
         policyRoot = root;
    }
    
    private FactTreeNode collapseFactTreeNode(String rootValue, Collection<FactTreeNode> children, FactMetaData factMetaData) {
        Map<String, Collection<FactTreeNode>> childMap = new HashMap<String, Collection<FactTreeNode>>(children.size());
        for (FactTreeNode child : children) {
            childMap.put(child.value, child.children);
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
        for (String key : jsonObject.keySet()) {
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
        Iterator<FactTreeNode> iter = factTreeNode.children.iterator();
        while (iter.hasNext()) {
            FactTreeNode child = iter.next();
            for (int j = 0; j < indent; j++) {
                writer.write("    ");
            }
            writer.write("\"");
            writer.write(child.value.replaceAll("\\\\", "\\\\").replaceAll("\"", "\\\""));
            writer.write("\": {");
            if (child.children.size() > 0) {
            } else {
                writer.write("\n");
                writePolicy(writer, child, indent+1);
            }
            writer.write ("}");
            if (iter.hasNext()) {
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
        return violationStore.getViolations();
    }
}