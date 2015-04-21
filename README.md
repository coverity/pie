Policy Instantiation and Enforcement (PIE)
==========================================

Introduction
------------

PIE is a framework for creating and managing security policies within Java web applications. PIE is designed to be general, so exactly how you use PIE is up you, but it comes out-of-the-box with modules for the Java [SecurityManager](http://docs.oracle.com/javase/7/docs/api/java/lang/SecurityManager.html) (which can enforce a policy for certain JVM operations like file and socket manipulation) and [Content Security Policy](http://www.w3.org/TR/CSP/) (which helps to mitigate XSS).

Like many security policy engines, PIE has two operating modes: a learning mode and an enforcement mode. In the learning mode, PIE internally logs any would-be violations of its security policies, and then updates the policy to whitelist the violation. Once learning mode is disabled, PIE strictly enforces the policy. What makes PIE unique is its generalized framework for understanding and simplifying security policies, making them easier for human consumption and verification, and making it more likely to identifying dynamically generated portions of policy requests (such as file paths or host names).

Below, you'll find some quick-start instructions to start using PIE, followed by a detailed description of its architecture including information on how to customize its behavior and extend PIE with policies tailored to your application.

Quick-Start
-----------

### Including PIE in your project

If you're using a Maven project, the easiest way to use PIE is to just add it as a dependency to your application.

    <dependency>
        <groupId>com.coverity.pie</groupId>
        <artifactId>pie-core</artifactId>
        <version>1.0</version>
    </dependency>
    <dependency>
        <groupId>com.coverity.pie.plugin</groupId>
        <artifactId>pie-sm</artifactId>
        <version>1.0</version>
    </dependency>
    <dependency>
        <groupId>com.coverity.pie.plugin</groupId>
        <artifactId>pie-csp</artifactId>
        <version>1.0</version>
    </dependency>

Notice how we included the SecurityManager (pie-sm) and Content Security Policy (pie-csp) plugins as separate dependencies. This allows you to pick-and-choose which PIE plugins to include in your application. If you're deploying your application to a Servlet 3.0 compatible container (like Tomcat or Jetty), PIE will automatically get picked up and utilized, so no further configuration is needed.

If you're not using Maven or you just don't want to include PIE in your pom, you can also copy the distributable JARs into your web containers common library directory. For example, if you're using Tomcat:

    cp pie-core/target/pie-core-1.0-dist.jar $TOMCAT_HOME/lib
    cp pie-sm/target/pie-sm-1.0.jar $TOMCAT_HOME/lib
    cp pie-csp/target-pie-csp-1.0.jar $TOMCAT_HOME/lib

Lastly, PIE has support for integrating into Dropwizard applications. In addition to adding the above dependencies to your pom, just add the PieBundle to your Application bootstrap:

    public class HelloWorldApplication extends Application<HelloWorldConfiguration> {
        ...
        @Override
        public void initialize(Bootstrap<HelloWorldConfiguration> bootstrap) {
            bootstrap.addBundle(new com.coverity.pie.dropwizard.PieBundle());
            ...
        }
        ...
    }

### Managing your policies
Once you startup your app, you should immediately see an initial (empty) policy file get created by PIE. By default, its put in the current working directory of your application/container (e.g. $TOMCAT\_HOME); information on changing this path is in the configuration section below.

By default, PIE will will simplify and save its policies every 30 seconds, as well as on the container shutdown (assuming the container is shutdown gracefully). If you want to manually adjust a policy, shutdown your application, make your changes to the file, and start it up again (it will read the policy file on startup).

The semantics of a policy file depend on particular policy module, but the general schema is a tree-based whitelist of allowed "facts." Policy files are JSON formatted, making it easy to manually inspect and update as desired. For example:

    $ cat securityManager.policy 
    {
       "file:/opt/tomcat/webapps/pebble-2.6.4/WEB-INF/lib/-": {
          "java.io.FilePermission": {
             "/home/tomcat/pebble": {
                "read,write": {}
             },
             "/home/tomcat/pebble/realm": {
                "read,write": {}
             },
             "/home/tomcat/pebble/realm/username.properties": {
                "read,write": {}
             },
             "/home/tomcat/tomcats/pebble/temp/*": {
                "read": {}
             },
             "/usr/lib/jvm/java-7-openjdk-amd64/jre/lib/xerces.properties": {
                "read": {}
             }
          }
          ...
       }
    }

In this case, we see that the policy grants permission to read and write the `/home/tomcat/pebble/realm/username.properties` file. We may realize that we really want to grant permission to all files in the directory instead. We could either make the application access another file in this directory (at which point PIE would extrapolate a policy which whitelists access to all files in the directory), or manually update this file.


### Configuring PIE
On startup, PIE looks for a file named pieConfig.properties either in the current working directory, or in the root of the classpath. You can put values in this file to customize the behavior of PIE or its modules (including disabling PIE and any of its modules). 


Integrating PIE into SDLC and testing
-------------------------------------

Generating a policy file while PIE is in learning mode requires actually using the application so that it can see permission requests. The best way to do this is to integrate PIE into your automated testing, and PIE provides a Maven plugin to help with this task.

Since your application server for automated testing may not be on the same machine from which you are driving your tests, this plugin allows your local Maven process to fetch policy violations and act on them. The plugin can be configured to update a local policy file with those violations and/or fail the Maven build if any policy violations are found. If the server is kept in learning mode, this allows individual tests to pass while enabling QA to recognize that the policy needs to be updated.

To add the Maven plugin to your build, add the following to the build plugins section of your pom:

    <plugin>
        <groupId>com.coverity.pie</groupId>
        <artifactId>pie-maven-plugin</artifactId>
        <version>1.0</version>
        <configuration>
            <serverUrl>http://qaserver.myapp.example.com:8080/</serverUrl>
            <pieConfig>pieConfig.properties</pieConfig>
            <pluginRoots>
                <pluginRoot>${maven.repo.local}/com/coverity/pie/plugin</pluginRoot>
            </pluginRoots>
        </configuration>
        <executions>
            <execution>
                <goals>
                    <goal>build-policy</goal>
                    <goal>check-violations</goal>
                </goals>
            </execution>
        </executions>
    </plugin>

The two goals build-policy and check-violations will either update the local policies files with any violations learned during the build, or will fail the build if any violations were logged.

The Maven plugin has several additional options, so read the documentation for more info!


Extending PIE
=============

The core of PIE provides a framework for initializing PIE modules and automatically simplifying and managing policy files. It is up to the modules themselves to provide classes which understand how to intelligently collapse (i.e. simplify) policy file entries (although there are several classes that can be extended to assist in simplification of policies which have typical patterns) and to hook into the relevant pieces of the application. The reader is advised to read this section, and then look at the SecurityManager and Content Security Policy modules as examples of how to extend PIE. Also in the repository is an example project that defines its own PIE module, utilizing Spring Security method-security enforcement. This is also a great example to look at in order to determine how to write your own module.

Architecture
-------------

The most important responsibility for a PIE module is to define how it enforces its policy on the target application, which is defined in an implementation of the PolicyEnforcer interface. This class will be passed a ServletContext on startup, but it is up to the module to determine how to then hook into the application. The SecurityManager module achieves this by supplying a SecurityContext to the JVM, which is static and therefore ignores the ServletContext entirely. The CSP module simply adds a Filter to the ServletContext. The Spring Security example application places itself (i.e. the PolicyEnforcer) into the ServletContext as an attribute, which is then used by the PieAccessDecisionManager (a bean which is additionally added to the Spring application context).

Once a PIE module has inserted itself into an application, it can then delegate security decisions to the PIE Policy object. Abstractly, each policy decision is based on an array of "facts," where each fact is simply a String that has context-dependent semantics. The policy is then just a collection of these fact arrays that has been whitelisted.

The default semantics provided by PIE is just literal String matching, with a no-op simplification engine. While this allows us to begin defining a policy for any context, it doesn't really provide much value. And although a PIE module would then immediately be functional, it is more useful if a PIE module fulfills its second role in defining semantics to the facts passed to the underlying Policy object.

Concretely, this is done by extending the FactMetaData interface which has methods defining a) how to simplify the facts of that type, b) how to match a fact against one from the policy file (which is helpful in the case that you've chosen to introduce something like a regular language into your policy), and c) what the FactMetaData is for the next fact in the array).

As an example, the SecurityManager receives its permission requests as an instance of the abstract Permission class. The enforcement engine serializes this into the following sequence of facts:
1. The originating code source of the permission (e.g. WEB-INF/lib/foo.jar).
2. The name of Permission instances concrete class (e.g. java.io.FilePermission).
3. The "name" from the permission (the FilePermission class defines its getName() as returning the name of the file in question).
4. The "action" from the permission (the FirePermission class defines its getActions() as returning read, write, and/or delete).

The SecurityManager module therefore defines the following FactMetaData classes:
1. CodeSourceFactMetaData, which will collapse anything under WEB-INF/lib (and call it "WEB-INF/lib/-").
2. PermissionClassFactMetaData, which doesn't enhance the default literal String matching, but which provides different FactMetaData classes depending on the particular fact on which it is operating. For example, given a "java.io.FilePermission" fact, it will return...
3. FileNameFactMetaData, which has path-collapsing and path-matching logic relevant to file paths (e.g. it will instruct PIE to collapse "/foo/bar/a" and "/foo/bar/b" to just "/foo/bar/\*").
4. CsvActionFactMetaData, which will collapse "read" and "write" actions to "read,write."

The specific implementation of FactMetaData will not generally effect the correctness of your PIE module, but will only effect its ability to simplify a policy (thus effecting how easy it is to manually inspect or verify the policy) and its ability to generalize and extrapolate (thus collapsing "/users/Alice.properties" and "/users/Bob.properties" to "/users/\*.properties") so that the policy isn't brittle.


FAQ
===

### Q: I'm already using a SecurityManager and/or Content Security Policy header. Can I still use PIE?

In general, yes, but the effect of chaining PIE with existing security policies depends on the particular module. The SecurityManager module is designed to check for an existing policy (such as Tomcat's default SecurityManager) and check delegate permission requests to it first. If that policy rejects the request, PIE operates on it as normal (by looking at its own policy and either logging violations in learning mode or rejecting the permission request in enforcement mode).

The CSP module is implemented by adding a filter to the Servlet context, and so its behavior is likely to depend on how it gets ordered with any other CSP implementation; in general the CSP module should not be combined with any other CSP implementation.

### Q: Can I just use PIE to log policy violations as a potential intrusion-detection system or as a way of manually building a policy independent of PIE?

Sure! Just leave PIE in report-only mode, and you can either manually inspect the generated policy or you can turn up PIE's logging to DEBUG (see the configuration section) and act on the observed violations in your application logs.

