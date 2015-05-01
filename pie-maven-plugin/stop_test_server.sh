#!/bin/sh -e

mvn exec:java -Dexec.classpathScope=test -Dexec.mainClass=com.coverity.security.pie.test.TestPieServer -Dexec.args=shutdown < /dev/null

