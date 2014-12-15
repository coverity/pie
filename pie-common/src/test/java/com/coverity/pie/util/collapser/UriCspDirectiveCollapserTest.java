package com.coverity.pie.util.collapser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.coverity.pie.policy.csp.CspPolicyEntry;

public class UriCspDirectiveCollapserTest {
    @Test
    public void testBasicCollapse() {
        final UriCspDirectiveCollapser collapser = new UriCspDirectiveCollapser(2);
        
        List<CspPolicyEntry> output = new ArrayList<CspPolicyEntry>(collapser.collapse(buildCspPolicy(
                new Object[] {
                        new Object[] {
                            "/a/b/c", new Object[] {
                                    new Object[] { "object-src", new String[] { "b.b.c.example.com", "f.b.c.example.com", "oof.rab.com", } },
                                    new Object[] { "script-src", new String[] { "a.b.c.example.com", "d.b.c.example.com", "foo.bar.com", } },
                            }
                        }, new Object[] {
                            "/a/b/d", new Object[] {
                                    new Object[] { "object-src", new String[] { "j.d.c.example.com", "k.d.c.example.com", "oof.rab.com", } },
                                    new Object[] { "script-src", new String[] { "h.d.c.example.com", "i.d.c.example.com", "foo.bar.com", } },
                            }
                        }, new Object[] {
                            "/c/d/e", new Object[] {
                                    new Object[] { "object-src", new String[] { "1", } },
                                    new Object[] { "script-src", new String[] { "2", } },
                            }
                        }, new Object[] {
                            "/c/d/f", new Object[] {
                                    new Object[] { "object-src", new String[] { "3", } },
                                    new Object[] { "script-src", new String[] { "4", } },
                            }
                        }, new Object[] {
                            "/c/g/h", new Object[] {
                                    new Object[] { "object-src", new String[] { "5", } },
                                    new Object[] { "script-src", new String[] { "6", } },
                            }
                        }, new Object[] {
                            "/c/g/j", new Object[] {
                                    new Object[] { "object-src", new String[] { "7", } },
                                    new Object[] { "script-src", new String[] { "8", } },
                            }
                        },
                })));
                
        Assert.assertEquals(toArray(output), new Object[] {
                new Object[] {
                        "/a/b/*", new Object[] {
                                new Object[] { "object-src", new String[] { "b.b.c.example.com", "f.b.c.example.com", "j.d.c.example.com", "k.d.c.example.com", "oof.rab.com", "oof.rab.com", } },
                                new Object[] { "script-src", new String[] { "a.b.c.example.com", "d.b.c.example.com", "foo.bar.com", "foo.bar.com", "h.d.c.example.com", "i.d.c.example.com", } },
                        }
                }, new Object[] {
                        "/c/**", new Object[] {
                                new Object[] { "object-src", new String[] { "1", "3", "5", "7", } },
                                new Object[] { "script-src", new String[] { "2", "4", "6", "8", } },
                        }
                },
            });
    }
    
    @Test
    public void testDoNotCollapseToRoot() {
        final UriCspDirectiveCollapser collapser = new UriCspDirectiveCollapser(2);
        
        List<CspPolicyEntry> output = new ArrayList<CspPolicyEntry>(collapser.collapse(buildCspPolicy(
                new Object[] {
                        new Object[] {
                            "/**", new Object[] {
                                    new Object[] { "script-src", new String[] { "'self'", } },
                                    new Object[] { "style-src", new String[] { "'self'", } },
                            }
                        }, new Object[] {
                            "/a/a", new Object[] {
                                    new Object[] { "script-src", new String[] { "1.com", } },
                            }
                        }, new Object[] {
                            "/a/b", new Object[] {
                                    new Object[] { "script-src", new String[] { "2.com", } },
                            }
                        },
                })));
                
        Assert.assertEquals(toArray(output), new Object[] {
                new Object[] {
                    "/**", new Object[] {
                            new Object[] { "script-src", new String[] { "'self'", } },
                            new Object[] { "style-src", new String[] { "'self'", } },
                    }
                }, new Object[] {
                    "/a/*", new Object[] {
                            new Object[] { "script-src", new String[] { "1.com", "2.com", } },
                    }
                },
            });
    }

    private static List<CspPolicyEntry> buildCspPolicy(Object[] definition) {
        List<CspPolicyEntry> entries = new ArrayList<CspPolicyEntry>(definition.length);
        for (Object entryDefnO : definition) {
            Object[] entryDefn = (Object[])entryDefnO;
            
            String uri = (String)entryDefn[0];
            Object[] directivesDefn = (Object[])entryDefn[1];
            
            Map<String, List<String>> directiveMap = new HashMap<String, List<String>>(directivesDefn.length);
            for (Object directiveO : directivesDefn) {
                Object[] directiveDefn = (Object[])directiveO;
                
                String directiveName = (String)directiveDefn[0];
                Object[] hostnames = (Object[])directiveDefn[1];
                
                List<String> hostnameList = new ArrayList<String>(hostnames.length);
                for (Object hostname : hostnames) {
                    hostnameList.add((String)hostname);
                }
                directiveMap.put(directiveName, hostnameList);
            }
            
            entries.add(new CspPolicyEntry(uri, directiveMap));
        }
        return entries;
    }
    
    private static Object[] toArray(Collection<CspPolicyEntry> entries) {
        final Comparator<Object[]> comparator = new StringZeroComparator();
        
        List<Object[]> uriDefns = new ArrayList<Object[]>(entries.size());
        for (CspPolicyEntry entry : entries) {
            List<Object[]> directiveDefns = new ArrayList<Object[]>(entry.getDirectives().size());
            
            for (Map.Entry<String, List<String>> directiveEntry : entry.getDirectives().entrySet()) {
                List<String> hostnames = new ArrayList<String>(directiveEntry.getValue());
                Collections.sort(hostnames);

                Object[] directiveDefn = new Object[2];
                directiveDefn[0] = directiveEntry.getKey();
                directiveDefn[1] = hostnames.toArray();
                directiveDefns.add(directiveDefn);
            }
            
            Collections.sort(directiveDefns, comparator);
            Object[] entryDefn = new Object[2];
            entryDefn[0] = entry.getUri();
            entryDefn[1] = directiveDefns.toArray();
            uriDefns.add(entryDefn);
        }
        Collections.sort(uriDefns, comparator);
        return uriDefns.toArray();
    }
    
    private static class StringZeroComparator implements Comparator<Object[]> {

        @Override
        public int compare(Object[] o1, Object[] o2) {
            return ((String)o1[0]).compareTo((String)o2[0]);
        }
        
    }
}
