#!/bin/sh -e

mvn exec:java -Dexec.classpathScope=test -Dexec.mainClass=com.coverity.security.pie.test.TestPieServer > /dev/null 2>/dev/null < /dev/null &
# FIXME: Find a better way to fork the server process, but wait until it's ready
sleep 5

