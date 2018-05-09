<p align="center"><img width="260" style="float: center;" style="display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/lazysodium.png" /></p>


# Lazysodium for Java

Lazysodium is a **Java 8+** crypto wrapper around a **near complete** implementation of the [Libsodium](https://github.com/jedisct1/libsodium) library, providing developers with a **smooth and effortless** experience. 


[![Build Status](https://semaphoreci.com/api/v1/terl/lazysodium-java/branches/master/badge.svg)](https://semaphoreci.com/terl/lazysodium-java)
[![Download](https://api.bintray.com/packages/terl/lazysodium-maven/lazysodium-java/images/download.svg) ](https://bintray.com/terl/lazysodium-maven/lazysodium-java/_latestVersion)

## Why Lazysodium
We created Lazysodium because we really wanted a solid cryptography library that would just work without fuss.

We were exasperated and annoyed with current Libsodium implementations as some of them were just poorly maintained, poorly managed and, plain and simply, poorly architected.

Thus, Lazysodium was born with the blessings of *Lazycode*, a part of [Terl](https://terl.co) that specialises in giving developers easy-to-use software and tools that just work. Read more about us below.

### The difference in code

We just wanted to entice you with a few snippets of code, to show you the ease of Lazysodium.

#### Using native functions

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

#### Using Lazysodium's lazy functions
You could use the above native functions **or** you could use the "Lazy" functions 😄
 
```java

long subKeyId = 1L;
String context = "Examples";
String masterKey = "a_master_key";
String subkeyString = lazySodium.cryptoKdfDeriveFromKey(subKeyId, context, masterKey);
```

As you can see Lazysodium's lazy functions **save you a lot of pain**!




## Get started

This section will help you get started with Lazysodium quickly (and with utmost laziness).

### Check
Lazysodium for Java requires:

* JDK 8 or higher.
* Gradle 4.7 or higher (if compiling and building).
* No effort whatsoever.


### Add 
This is how to get started with Lazysodium in your Java projects. Substitute `VERSION_NUMBER` with the number provided in the following button:

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

```xml
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


## Contributing
Contributions are welcome! For more information please see the [Contributor's Guide](https://github.com/terl/lazysodium-java/wiki/Contributor%27s-Guide).

## Licence
The licence is `MPLv2` as it is a nice middle-ground between copyleft and copyright. I know some developer's would rather not get bogged down in legalities (and we don't blame them). Therefore a brief read of [Mozilla's MPLv2 FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/#apply) will show you the luxuries afforded to you by the `MPLv2` Licence. Some luxuries include:

 * **You can use this library commercially.** 
 * You can incorporate this library into other projects (just so long as you don't modify any files - see the point immediately below this one).
 * You can modify this library internally within your organisation or company but if you distribute those changes, then you must contribute those changes back to this project or make those changes publicly available.
 * The above point fosters a **better community** and so the library is **constantly improved**.
 
<p></p>

<a href="https://terl.co"><img width="80" style="float: left: display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/terl_slant.png" /></a>

<sup>Created by the wizards at [Terl](https://terl.co).</sup>

