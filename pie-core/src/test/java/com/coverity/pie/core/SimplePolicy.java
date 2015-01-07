package com.coverity.pie.core;

public class SimplePolicy extends Policy {

    @Override
    public String getName() {
        return "simple";
    }

    @Override
    public FactMetaData getRootFactMetaData() {
        return SimpleFactMetaData.getInstance();
    }
    
    private static class SimpleFactMetaData implements FactMetaData {

        private static final SimpleFactMetaData instance = new SimpleFactMetaData();
        
        private SimpleFactMetaData() {
        }
        
        public static SimpleFactMetaData getInstance() {
            return instance;
        }
        
        @Override
        public StringCollapser getCollapser(PolicyConfig policyConfig) {
            return NullStringCollapser.getInstance();
        }

        @Override
        public boolean matches(String matcher, String matchee) {
            return matcher.equals(matchee);
        }

        @Override
        public FactMetaData getChildFactMetaData(String fact) {
            return getInstance();
        }
        
    }

}
