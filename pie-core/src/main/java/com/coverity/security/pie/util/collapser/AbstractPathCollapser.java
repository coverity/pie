package com.coverity.security.pie.util.collapser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An abstraction of common behavior for collapsers which collapse paths based on "path" semantics. Such examples
 * include file system paths (e.g. /tmp/foo/bar), URLs (e.g. http://foo.bar.com/a/b/c), hostnames (e.g. foo.bar.com),
 * and system properties (e.g. foo.baz.bar).
 */
public abstract class AbstractPathCollapser {

    /**
     * A data-container class for parsed abstraction of paths. Paths may contain non-path components (in a URL, this
     * might include the host name and port) and the path components.
     */
    protected final static class PathName {
        private final String[] pathComponents;
        private final String[] nonPathComponents;
        
        public PathName(String[] pathComponents, String[] nonPathComponents) {
            this.pathComponents = pathComponents;
            this.nonPathComponents = nonPathComponents;
        }

        public String[] getPathComponents() {
            return pathComponents;
        }

        public String[] getNonPathComponents() {
            return nonPathComponents;
        }
        
    }
    
    private final String fileStar;
    private final String dirStar;
    private final int collapseThreshold;
    private final int minDepth;

    /**
     * @param fileStar The wildcard which represents matching all children in the current path, but not descendants of
     *                 children.
     * @param dirStar The wildcard which represents matching all descendants in the current path.
     * @param collapseThreshold The minimum number of children that must show up in the same level of path before the
     *                          collapser decides to combine all children using the fileStar or dirStar wildcard.
     * @param minDepth The minimum depth to which collapsing will be performed. For example, if minDepth is 2, then
     *                 the collapser will not collapse /a/* and /b/* into /-
     */
    protected AbstractPathCollapser(String fileStar, String dirStar, int collapseThreshold, int minDepth) {
        this.fileStar = fileStar;
        this.dirStar = dirStar;
        this.collapseThreshold = collapseThreshold;
        this.minDepth = minDepth;
    }
    
    private static boolean nullEquals(String a, String b) {
        if (a == null) {
            return b == null;
        }
        return a.equals(b);
    }
    private static boolean nullEquals(String[] a, String[] b) {
        if (a == null) {
            return b == null;
        }
        if (b == null) {
            return false;
        }
        if (a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if(!nullEquals(a[i], b[i])) {
                return false;
            }
        }
        return true;
    }

    /**
     * The primary interface for using the AbstractPathCollapser
     * @param paths The paths to be collapsed.
     * @return The collapsed output.
     */
    protected final <T> Map<PathName, Collection<T>> collapsePaths(Map<PathName, Collection<T>> paths) {
        
        boolean anyCollapsed = true;
        while (anyCollapsed) {
            anyCollapsed = false;
            
            List<PathName> newPaths = new ArrayList<PathName>();
            for (Map.Entry<PathName, Collection<T>> pathNameA : paths.entrySet()) {
                String[] a = pathNameA.getKey().getPathComponents();
                
                // Do not collapse anything already at minDepth or which would collapse to below minDepth
                if (a.length <= minDepth || (a.length == minDepth+1 && (a[a.length-1].equals(fileStar) || a[a.length-1].equals(dirStar)))) {
                    continue;
                }
                
                int numMatches = 0;
                for (Map.Entry<PathName, Collection<T>> pathNameB : paths.entrySet()) {
                    if (pathNameA.getKey() == pathNameB.getKey()) {
                        continue;
                    }
                    if (!nullEquals(pathNameA.getKey().getNonPathComponents(), pathNameB.getKey().getNonPathComponents())) {
                        continue;
                    }
                    String[] b = pathNameB.getKey().getPathComponents();
                    // If they are exactly equal, ignore this
                    if (nullEquals(a, b)) {
                        continue;
                    }
                    
                    if (a.length == b.length) {
                        if (arePathsMatch(a, b)) {
                            numMatches += 1;
                        }
                    }
                }
                
                if (numMatches >= collapseThreshold-1) {
                    if (a[a.length-1].equals(fileStar) || a[a.length-1].equals(dirStar)) {
                        // If this is relative root
                        if (a.length == 1) {
                            // If this isn't dirStar (i.e. is "*" but not "-") then add the dirStar root
                            if (!a[0].equals("dirStar")) {
                                newPaths.add(new PathName(new String[] { dirStar }, pathNameA.getKey().getNonPathComponents()));
                            }
                        } else if (a.length > 2 || !a[0].equals("") || !a[1].equals(dirStar)) {
                            // ^ If this is root path and have dirStar (i.e. this is "/-") then don't make a new path
                            String[] path = new String[a.length-1];
                            for (int i = 0; i < a.length-2; i++) {
                                path[i] = a[i];
                            }
                            path[a.length-2] = dirStar;
                            newPaths.add(new PathName(path, pathNameA.getKey().getNonPathComponents()));
                            anyCollapsed = true;
                        }
                    } else {
                        String[] path = new String[a.length];
                        for (int i = 0; i < a.length-1; i++) {
                            path[i] = a[i];
                        }
                        path[a.length-1] = fileStar;
                        newPaths.add(new PathName(path, pathNameA.getKey().getNonPathComponents()));
                        anyCollapsed = true;
                    }
                }
                
            }
            
            Map<PathName, Collection<T>> newPathMap = new HashMap<PathName, Collection<T>>();
            for (PathName pathName : newPaths) {
                boolean alreadyAdded = false;
                for (PathName newPathName : newPathMap.keySet()) {
                    if (pathNameMatches(newPathName, pathName)) {
                        alreadyAdded = true;
                        break;
                    }
                }
                if (!alreadyAdded) {
                    newPathMap.put(pathName, new ArrayList<T>());
                }
            }
            for (Map.Entry<PathName, Collection<T>> pathNameEntry : paths.entrySet()) {
                PathName alreadyAdded = null;
                for (PathName newPathName : newPathMap.keySet()) {
                    if (pathNameMatches(newPathName, pathNameEntry.getKey())) {
                        alreadyAdded = newPathName;
                        break;
                    }
                }
                if (alreadyAdded != null) {
                    if (pathNameEntry.getValue() != null) {
                        newPathMap.get(alreadyAdded).addAll(pathNameEntry.getValue());
                    }
                    anyCollapsed = true;
                } else {
                    newPathMap.put(pathNameEntry.getKey(), pathNameEntry.getValue() != null ? new ArrayList<T>(pathNameEntry.getValue()) : new ArrayList<T>());
                }
            }
            
            boolean duplicateCollapse = true;
            while (duplicateCollapse) {
                duplicateCollapse = false;
                for (Map.Entry<PathName, Collection<T>> pathNameEntry : newPathMap.entrySet()) {
                    PathName alreadyAdded = null;
                    for (PathName newPathName : newPathMap.keySet()) {
                        if (pathNameEntry.getKey() == newPathName) {
                            continue;
                        }
                        if (pathNameMatches(newPathName, pathNameEntry.getKey())) {
                            alreadyAdded = newPathName;
                            break;
                        }
                    }
                    if (alreadyAdded != null) {
                        if (pathNameEntry.getValue() != null) {
                            newPathMap.get(alreadyAdded).addAll(pathNameEntry.getValue());
                        }
                        newPathMap.remove(pathNameEntry.getKey());
                        duplicateCollapse = true;
                        anyCollapsed = true;
                        break;
                    }
                }
            }
            
            paths.clear();
            paths.putAll(newPathMap);
        }
        
        return paths;
    }

    /**
     * A utility method to decide if the path-spec matches another. For convenience, it is exposed to subclasses.
     * @param a The matcher.
     * @param b The matchee.
     * @return True if all paths mathched by b would also be matched by a.
     */
    protected boolean arePathsMatch(String[] a, String[] b) {
        // If both end with dirStar or fileStar...
        if ((a[a.length-1].equals(fileStar) || a[a.length-1].equals(dirStar))
                && (b[b.length-1].equals(fileStar) || b[b.length-1].equals(dirStar))) {
            // Then match if everything but the last two parts are the same
            for (int k = 0; k < a.length-2; k++) {
                if (!a[k].equals(b[k])) {
                    return false;
                }
            }
            return true;
        } else {
            // Only match if neither is a fileStar/dirStir
            if (a[a.length-1].equals(fileStar) || a[a.length-1].equals(dirStar)
                    || b[b.length-1].equals(fileStar) || b[b.length-1].equals(dirStar)) {
                return false;
            }
            
            // Match if everything but last part is the same
            for (int k = 0; k < a.length-1; k++) {
                if (!a[k].equals(b[k])) {
                    return false;
                }
            }
            return true;
        }
    }

    /**
     * A utility method to decide if a PathName instance matches another. For convenience, it is exposed to subclasses.
     * @param matcher The matcher.
     * @param matchee The matchee.
     * @return True if the non-path components are identically equal and anything matched by the matcher's path
     * components would also match the matchee's path components.
     */
    protected boolean pathNameMatches(PathName matcher, PathName matchee) {
        if (!nullEquals(matcher.getNonPathComponents(), matchee.getNonPathComponents())) {
            return false;
        }
        
        String[] a = matcher.getPathComponents();
        String[] b = matchee.getPathComponents();
        
        if (a[a.length-1].equals(dirStar)) {
            if (b.length < a.length) {
                return false;
            }
            for (int i = 0; i < a.length-1; i++) {
                if (!a[i].equals(b[i])) {
                    return false;
                }
            }
            return true;
        } else if (a[a.length-1].equals(fileStar)) {
            if (a.length != b.length) {
                return false;
            }
            if (!b[b.length-1].equals(fileStar) && b[b.length-1].equals(dirStar)) {
                return false;
            }
            for (int i = 0; i < a.length-1; i++) {
                if (!a[i].equals(b[i])) {
                    return false;
                }
            }
            return true;
        } else if (a.length == b.length) {
            for (int i = 0; i < a.length; i++) {
                if (!a[i].equals(b[i])) {
                    return false;
                }
            }
            return true;
        } else {
            return false;
        }
    }

}
