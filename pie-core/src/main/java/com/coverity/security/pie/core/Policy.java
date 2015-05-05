package com.coverity.security.pie.core;

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
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.json.JSONObject;

import com.coverity.security.pie.util.IOUtil;

/**
 * An abstract representation of a security policy. This abstract class contains common methods, such as deciding
 * whether or not an array of facts is implied (i.e. whitelisted) by the security policy, and methods for collapsing
 * (i.e. simplifying) the security policy.
 */
public abstract class Policy {
    protected final static class FactTreeNode {
        private final String value;
        private final Collection<FactTreeNode> children;
        
        public FactTreeNode(String value) {
            this.value = value;
            this.children = new ArrayList<FactTreeNode>();
        }
    }
    
    private PolicyConfig policyConfig = null;
    private FactTreeNode policyRoot = new FactTreeNode(null);
    private ViolationStore violationStore = new ViolationStore();
    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    
    public abstract String getName();
    public abstract FactMetaData getRootFactMetaData();
    
    public void setPolicyConfig(PolicyConfig policyConfig) {
        this.policyConfig = policyConfig;
    }

    /**
     * Decides if the concrete instance of facts is implied (i.e. whitelisted) by the security policy.
     * @param facts The concrete instance of facts.
     * @return Whether or not the instance of facts is allowed by the security policy.
     */
    protected final boolean implies(String ... facts) {
        int factIndex = 0;
        FactTreeNode node = policyRoot;
        FactMetaData factMetaData = getRootFactMetaData();

        Lock lock = null;
        try {
            lock = readWriteLock.readLock();
            lock.lock();
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
        } finally {
            if (lock != null) {
                lock.unlock();
            }
        }
    }

    /**
     * This returns the collection of fact arrays which are allowed by this security policy, filtered by the facts
     * passed in as arguments. NULL parameters in the fact array are treated as wildcards by the filter, and any
     * non-NULL parameters are matched according to the policy's usual matching rules.
     * @param facts The concrete fact instances used to filter the returned collection.
     * @return A collection of fact arrays that are allowed by the policy, filtered by the methods input.
     */
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

    /**
     * Updates the policy to whitelist all previously observed policy violations.
     */
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

    /**
     * Updates the policy to include the concrete array of facts.
     * @param facts The fact array which should be whitelisted by the policy.
     */
    protected final void addGrant(String ... facts) {
        FactTreeNode node = policyRoot;
        FactMetaData metaData = getRootFactMetaData();

        Lock lock = null;
        try {
            lock = readWriteLock.writeLock();
            lock.lock();

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
        } finally {
            if (lock != null) {
                lock.unlock();
            }
        }
    }

    /**
     * Performs policy simplification.
     */
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
        childMap = factMetaData.getCollapser(policyConfig).collapse(childMap);
        
        FactTreeNode factTreeNode = new FactTreeNode(rootValue);
        for (Map.Entry<String, Collection<FactTreeNode>> entry : childMap.entrySet()) {
            factTreeNode.children.add(collapseFactTreeNode(
                    entry.getKey(), entry.getValue(), factMetaData.getChildFactMetaData(entry.getKey())));
        }
        return factTreeNode;
    }

    /**
     * Reads a PIE security policy from the reader argument, replacing any current policy data with what is read in.
     *
     * @param reader The reader with the raw policy content.
     * @throws IOException
     */
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

    /**
     * Writes the raw PIE security policy to the writer object.
     *
     * @param writer The writer which will receive the raw security policy.
     * @throws IOException
     */
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
            writer.write(child.value.replaceAll("\\\\", "\\\\\\\\").replaceAll("\"", "\\\\\\\""));
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

    /**
     * Appends the observed policy violation to this policy's list of violations.
     * @param facts
     */
    protected final void logViolation(String ... facts) {
        synchronized (violationStore) {
            violationStore.logViolation(facts);
        }
    }

    /**
     * @return Returns all distinct violations previously observed by this policy (as passed into logViolation()).
     */
    public String[][] getViolations() {
        synchronized (violationStore) {
            return violationStore.getViolations();
        }
    }

    /**
     * @param sinceTime A filter indicating the minimum time for which observed violations will be returned.
     * @return Returns all distinct violations previously observed by this policy (as passed into logViolation()) that have
     * occurred since the sinceTime argument (in Unix-time milliseconds).
     */
    public String[][] getViolations(long sinceTime) {
        synchronized (violationStore) {
            return violationStore.getViolations(sinceTime);
        }
    }
}
