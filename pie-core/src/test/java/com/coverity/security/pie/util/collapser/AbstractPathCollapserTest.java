package com.coverity.security.pie.util.collapser;

import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;

public class AbstractPathCollapserTest {

    private static class MockFilePathCollapser extends AbstractPathCollapser {

        protected MockFilePathCollapser(int collapseThreshold, int minDepth) {
            super("*", "-", collapseThreshold, minDepth);
        }

        public <T> Map<String[], Collection<T>> collapse(Map<String[], Collection<T>> input) {
            Map<PathName, Collection<T>> inputMap = new HashMap<PathName, Collection<T>>(input.size());
            for (Map.Entry<String[], Collection<T>> fileEntry : input.entrySet()) {
                inputMap.put(new PathName(fileEntry.getKey(), null), fileEntry.getValue());
            }
            Map<PathName, Collection<T>> outputMap = collapsePaths(inputMap);
            Map<String[], Collection<T>> output = new HashMap<String[], Collection<T>>(outputMap.size());
            for (Map.Entry<PathName, Collection<T>> pathEntry : outputMap.entrySet()) {
                output.put(pathEntry.getKey().getPathComponents(), pathEntry.getValue());
            }
            return output;
        }
    }

    @Test
    public void testCollapseFileStarInRelativeRoot() {
        Collection<String[]> props = new MockFilePathCollapser(2, -1).collapse(nullMap(Arrays.asList(
                new String[] { "*" },
                new String[] { "-" }))).keySet();
        assertEquals(props.size(), 1);
        assertEquals(props.iterator().next(), new String[] { "-" });
    }

    @Test
    public void doNotCollapseRepeatedFiles() {
        Collection<String[]> props = new MockFilePathCollapser(2, -1).collapse(nullMap(Arrays.asList(
                new String[] { "a", "b", "c" },
                new String[] { "a", "b", "c" },
                new String[] { "a", "b", "c" }))).keySet();
        assertEquals(props.size(), 1);
        assertEquals(props.iterator().next(), new String[] { "a", "b", "c" });
    }

    private static Map<String[], Collection<Void>> nullMap(Collection<String[]> keys) {
        Map<String[], Collection<Void>> result = new HashMap<>(keys.size());
        for (String key[] : keys) {
            result.put(key, null);
        }
        return result;
    }

}
