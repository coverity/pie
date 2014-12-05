package com.coverity.pie.policy.csp;


public class CspViolation {
    private final String documentUri;
    private final String blockedUri;
    private final String violatedDirectiveName;
    
    public CspViolation(String documentUri, String blockedUri, String violatedDirectiveName) {
        this.documentUri = documentUri;
        this.blockedUri = blockedUri;
        this.violatedDirectiveName = violatedDirectiveName;
    }

    public String getDocumentUri() {
        return documentUri;
    }

    public String getBlockedUri() {
        return blockedUri;
    }

    public String getViolatedDirectiveName() {
        return violatedDirectiveName;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result
                + ((blockedUri == null) ? 0 : blockedUri.hashCode());
        result = prime * result
                + ((documentUri == null) ? 0 : documentUri.hashCode());
        result = prime
                * result
                + ((violatedDirectiveName == null) ? 0 : violatedDirectiveName
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
        CspViolation other = (CspViolation) obj;
        if (blockedUri == null) {
            if (other.blockedUri != null)
                return false;
        } else if (!blockedUri.equals(other.blockedUri))
            return false;
        if (documentUri == null) {
            if (other.documentUri != null)
                return false;
        } else if (!documentUri.equals(other.documentUri))
            return false;
        if (violatedDirectiveName == null) {
            if (other.violatedDirectiveName != null)
                return false;
        } else if (!violatedDirectiveName.equals(other.violatedDirectiveName))
            return false;
        return true;
    }
    
}
