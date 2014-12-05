package com.coverity.pie.util.collapser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.coverity.pie.util.StringUtil;

public class FilePathCollapser extends AbstractPathCollapser<Void> {

    public FilePathCollapser(int collapseThreshold) {
        super("*", "-", collapseThreshold);
    }

    public Collection<String> collapse(Collection<String> input) {
        Map<PathName, Collection<Void>> inputMap = new HashMap<PathName, Collection<Void>>(input.size());
        for (String file : input) {
            inputMap.put(new PathName(file.split("/"), null), null);
        }
        Map<PathName, Collection<Void>> outputMap = collapsePaths(inputMap);
        Collection<String> output = new ArrayList<String>(outputMap.size());
        for (PathName pathName : outputMap.keySet()) {
            output.add(StringUtil.join("/", pathName.getPathComponents()));
        }
        return output;
    }
}
