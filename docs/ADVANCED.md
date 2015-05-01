Advanced Documentation
======================

This document covers topics that will be helpful if you want to use additional PIE modules, build your own, or tweak the way PIE interprets and simplifies policies.

Including other PIE modules in your project
-------------------------------------------

If you included PIE as a Maven dependency of your project, then you can just include any additional PIE modules as dependencies:

    <dependency>
        <groupId>com.coverity.security.pie.plugin</groupId>
        <artifactId>pie-csp</artifactId>
        <version>1.0</version>
    </dependency>

Alternatively, if you put PIE directly in your container's classpath (e.g. Tomcat's lib directory), then just add that module's JAR (along with the pie-core JAR) to the classpath.


Managing PIE policies
---------------------

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

In this case, we see that the policy grants permission to read and write the `/home/tomcat/pebble/realm/username.properties` file. We may realize that we really want to grant permission to all files in the directory instead. We could either make the application access another file in this directory (at which point the heuristic for the SecurityManager simplification of java.io.FilePermission children would extrapolate a policy which whitelists access to all files in the directory), or manually update this file.


Extending PIE
=============

The core of PIE provides a framework for initializing PIE modules and automatically simplifying and managing policy files. It is up to the modules themselves to provide classes which understand how to intelligently collapse (i.e. simplify) policy file entries (although there are several classes that can be extended to assist in simplification of policies which have typical patterns) and to hook into the relevant pieces of the application. The reader is advised to read this section, and then look at the SecurityManager and Content Security Policy modules as examples of how to extend PIE. Also in the repository is an example project that defines its own PIE module, utilizing Spring Security method-security enforcement. This is also a great example to look at in order to determine how to write your own module.

Architecture
------------

The most important responsibility for a PIE module is to define how it enforces its policy on the target application, which is defined in an implementation of the PolicyEnforcer interface. This class will be passed a ServletContext on startup, but it is up to the module to determine how to then hook into the application. The SecurityManager module achieves this by supplying a SecurityContext to the JVM, which is static and therefore ignores the ServletContext entirely. The CSP module simply adds a Filter to the ServletContext. The Spring Security example application places itself (i.e. the PolicyEnforcer) into the ServletContext as an attribute, which is then used by the PieAccessDecisionManager (a bean which is additionally added to the Spring application context).

Once a PIE module has inserted itself into an application, it can then delegate security decisions to the PIE Policy object. Abstractly, each policy decision is based on an array of "facts," where each fact is simply a String that has context-dependent semantics. The policy is then just a collection of these fact arrays that has been whitelisted.

The default semantics provided by PIE is just literal String matching, with a no-op simplification engine. While this allows us to begin defining a policy for any context, it doesn't really provide much value. And although a PIE module would then immediately be functional, it is more useful if a PIE module fulfills its second role in defining semantics to the facts passed to the underlying Policy object.

Concretely, this is done by extending the FactMetaData interface which has methods defining a) how to simplify the facts of that type, b) how to match a fact against one from the policy file (which is helpful in the case that you've chosen to introduce something like a regular language into your policy), and c) what the FactMetaData is for the next fact in the array).

As an example, the SecurityManager receives its permission requests as an instance of the abstract Permission class. The enforcement engine serializes this into the following sequence of facts:

1. The originating code source of the permission (e.g. `WEB-INF/lib/foo.jar`).
2. The name of Permission instances concrete class (e.g. java.io.FilePermission).
3. The "name" from the permission (the FilePermission class defines its getName() as returning the name of the file in question).
4. The "action" from the permission (the FirePermission class defines its getActions() as returning read, write, and/or delete).

The SecurityManager module therefore defines the following FactMetaData classes:

1. CodeSourceFactMetaData, which will collapse anything under WEB-INF/lib (and call it `WEB-INF/lib/-`).
2. PermissionClassFactMetaData, which doesn't enhance the default literal String matching, but which provides different FactMetaData classes depending on the particular fact on which it is operating. For example, given a "java.io.FilePermission" fact, it will return...
3. FileNameFactMetaData, which has path-collapsing and path-matching logic relevant to file paths (e.g. it will instruct PIE to collapse `/foo/bar/a` and `/foo/bar/b` to just `/foo/bar/*`).
4. CsvActionFactMetaData, which will collapse "read" and "write" actions to "read,write."

The specific implementation of FactMetaData will not generally effect the correctness of your PIE module, but will only effect its ability to simplify a policy (thus effecting how easy it is to manually inspect or verify the policy) and its ability to generalize and extrapolate (thus collapsing `/users/Alice.properties` and `/users/Bob.properties` to `/users/*.properties`) so that the policy isn't brittle.


FAQ
===

### Q: I'm already using a SecurityManager and/or Content Security Policy header. Can I still use PIE?

In general, yes, but the effect of chaining PIE with existing security policies depends on the particular module. The SecurityManager module is designed to check for an existing policy (such as Tomcat's default SecurityManager) and check delegate permission requests to it first. If that policy rejects the request, PIE operates on it as normal (by looking at its own policy and either logging violations in learning mode or rejecting the permission request in enforcement mode).

The CSP module is implemented by adding a filter to the Servlet context, and so its behavior is likely to depend on how it gets ordered with any other CSP implementation; in general the CSP module should not be combined with any other CSP implementation.

### Q: Can I just use PIE to log policy violations as a potential intrusion-detection system or as a way of manually building a policy independent of PIE?

Sure! Just leave PIE in report-only mode, and you can either manually inspect the generated policy or you can turn up PIE's logging to DEBUG (see the configuration section) and act on the observed violations in your application logs.


