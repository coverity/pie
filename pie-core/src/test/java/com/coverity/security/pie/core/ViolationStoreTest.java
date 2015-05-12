package com.coverity.security.pie.core;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class ViolationStoreTest {
    @Test
    public void testGetViolationsSinceTime() throws InterruptedException {
        ViolationStore violationStore = new ViolationStore();
        long startTime = System.currentTimeMillis();
        violationStore.logViolation("a", "b", "c");
        violationStore.logViolation("a", "b", "d");
        violationStore.logViolation("a", "b", "e");

        Thread.sleep(5L);
        long finishTime = System.currentTimeMillis();
        assertEquals(violationStore.getViolations(startTime).length, 3);
        assertEquals(violationStore.getViolations(finishTime).length, 0);

        // This matches an above violation, which should reset its violation time to now
        violationStore.logViolation("a", "b", "d");
        assertEquals(violationStore.getViolations(startTime).length, 3);
        assertEquals(violationStore.getViolations(finishTime).length, 1);
    }
}
