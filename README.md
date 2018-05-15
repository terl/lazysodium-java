<p align="center"><img width="260" style="float: center;" style="display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/lazysodium-plain.png" /></p>


# Lazysodium for Java

Lazysodium is a **complete** Java (JNA) wrapper over the [Libsodium](https://github.com/jedisct1/libsodium) library that provides developers with a **smooth and effortless** cryptography experience.


[![Build Status](https://semaphoreci.com/api/v1/terl/lazysodium-java/branches/master/badge.svg)](https://semaphoreci.com/terl/lazysodium-java)
[![Download](https://api.bintray.com/packages/terl/lazysodium-maven/lazysodium-java/images/download.svg) ](https://bintray.com/terl/lazysodium-maven/lazysodium-java/_latestVersion)

## Why Lazysodium
We created Lazysodium because we really wanted a solid cryptography library that would just work without fuss.

We were exasperated and annoyed with current Libsodium implementations as some of them were just poorly maintained, poorly managed and, plain and simply, poorly architected.

Thus, Lazysodium was born with the blessings of *Lazycode*, a part of [Terl](https://terl.co) that specialises in giving developers easy-to-use software and tools that just work. Read more about us below.

#### Here's what it's like to use native functions

```java
byte[] subkey = subkey[32];
int subkeyLen = subkey.length;
long subkeyId = 1L;
byte[] context = "Examples".getBytes(StandardCharsets.UTF_8);
byte[] masterKey = "a_master_key".getBytes(StandardCharsets.UTF_8);
int result = lazySodium.cryptoKdfDeriveFromKey(subkey, subkeyLen, subkeyId, context, masterKey);

// Now check the result
if (res == 0) {
    // We have a positive result. Let's store it in a database.
    String subkeyString = new String(subkey, StandardCharsets.UTF_8);
}
```

#### Here's what it's like to use Lazysodium's lazy functions
You could use the above native functions **or** you could use the "Lazy" functions 😄
 
```java

long subKeyId = 1L;
String context = "Examples";
String masterKey = "a_master_key";
String subkeyString = lazySodium.cryptoKdfDeriveFromKey(subKeyId, context, masterKey);
```

As you can see Lazysodium's lazy functions **save you a lot of pain**!


<br>

## Get started

This section will help you get started with Lazysodium quickly (and with utmost laziness).

### Requirements
Lazysodium for Java requires:

* JDK 8 or higher.
* Gradle 4.7 or higher (if compiling and building).
* No effort whatsoever.


### Add 
If you didn't know already, all Java libraries are hosted on a central repository. Lazysodium is hosted on [Bintray](https://bintray.com/terl/lazysodium-maven). This is important because you need to configure your build tool to pull and cache Lazysodium's packages from Bintray. The process is simple for Android projects... It's as simple as adding a few lines to your top-level `build.gradle` file.

```groovy
allprojects {
    repositories {
        google()
        jcenter()
        
        // Add this line here!
        maven {
            url  "https://dl.bintray.com/terl/lazysodium-maven"
        }
    }
}
```

The process of adding a new repository is different depending on what build tool you use. A quick Google or [DuckDuckGo](https://duckduckgo.com/?q=adding+a+repository+to+gradle+or+maven+or+sbt&t=hg&ia=qa) search can help.


Now, after adding the above, all you have to do is tell your build tool what package/artifact to include. Substitute `VERSION_NUMBER` with the number provided in the following button:

[![Download](https://api.bintray.com/packages/terl/lazysodium-maven/lazysodium-java/images/download.svg) ](https://bintray.com/terl/lazysodium-maven/lazysodium-java/_latestVersion)




##### Gradle

```groovy
dependencies {
    // ...
    implementation "com.goterl.lazycode:lazysodium-java:VERSION_NUMBER"
}
```

##### Maven

```xml
<dependency>
  <groupId>com.goterl.lazycode</groupId>
  <artifactId>lazysodium-java</artifactId>
  <version>VERSION_NUMBER</version>
  <type>pom</type>
</dependency>
```

##### Ivy

```
<dependency org='com.goterl.lazycode' name='lazysodium-java' rev=VERSION_NUMBER'>
  <artifact name='lazysodium-java' ext='pom' ></artifact>
</dependency>
```


##### SBT

```sbt
libraryDependencies += "com.goterl.lazycode" % "lazysodium-java" % "VERSION_NUMBER"
```

### Learn
For **documentation, roadmap, compiling, usage, etc** we invite you to head over to the [wiki](https://github.com/terl/lazysodium-java/wiki).


### Contribute
Contributions are welcome! For more information please see the [Contributor's Guide](https://github.com/terl/lazysodium-java/wiki/Contributor%27s-Guide).

<br>
<br>

<a href="https://terl.co"><img width="100" style="float: left: display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/terl_slant.png" /></a>

Created by the wizards at [Terl](https://terl.co).

