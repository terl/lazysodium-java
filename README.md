<p align="center"><img width="260" style="float: center;" style="display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/lazysodium-plain.png" /></p>


# Lazysodium for Java

Lazysodium is a **complete** Java (JNA) wrapper over the [Libsodium](https://github.com/jedisct1/libsodium) library that provides developers with a **smooth and effortless** cryptography experience.


[![Build Status](https://semaphoreci.com/api/v1/terl/lazysodium-java/branches/master/badge.svg)](https://semaphoreci.com/terl/lazysodium-java)
[![Download](https://api.bintray.com/packages/terl/lazysodium-maven/lazysodium-java/images/download.svg) ](https://bintray.com/terl/lazysodium-maven/lazysodium-java/_latestVersion)

## Help us grow
Lazysodium needs your support for it to continue being maintained and improved. Even if you put forward £1/$1/€1 it still means a lot for us. Your money would go into improving our open-source projects first and foremost. If you want to find out more, use your preffered donation platform. 

Patreon only has recurring subscriptions and rewards. Liberapay is another route you could take for subscription. We're also setting up our own system that allows one-off support.

<a href="https://www.patreon.com/terlacious"><img src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/patron_button.png" width="140" /></a>
<br>
<a href="https://liberapay.com/terlacious/"><img src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/liberapay.png" width="68" /></a>

[Or, use our system for one time support payments. Supports over 100 currencies.](https://terl.co/support-us)

<br> 

## Why Lazysodium
We created Lazysodium because we really wanted a solid cryptography library that would just work without fuss.

We were exasperated and annoyed with current Libsodium implementations as some of them were just poorly maintained, poorly managed and, plain and simply, poorly architected.

Thus, Lazysodium was born with the blessings of *Lazycode*, a part of [Terl](https://terl.co) that specialises in giving developers easy-to-use software and tools that just work. Read more about us below.

### Using the native functions

```java
byte[] subkey = subkey[32];
byte[] context = "Examples".getBytes(StandardCharsets.UTF_8);
byte[] masterKey = "a_master_key".getBytes(StandardCharsets.UTF_8);
int result = lazySodium.cryptoKdfDeriveFromKey(subkey, subkey.length, 1L, context, masterKey);

// Now check the result
if (res == 0) {
    // We have a positive result. Let's store it in a database.
    String subkeyString = new String(subkey, StandardCharsets.UTF_8);
}
```

#### Or use Lazysodium's lazy functions
You could use the above native functions **or** you could use the "Lazy" functions 😄
 
```java
String context = "Examples";
String masterKey = "a_master_key";
String subkeyString = lazySodium.cryptoKdfDeriveFromKey(1L, context, masterKey);
// Now store in database or something
```

As you can see Lazysodium's lazy functions **save you a lot of pain**!


<br>

## Quick start

This is by no means a comprehensive introduction to Lazysodium. Please view the [official documentation](https://docs.lazycode.co/lazysodium/installation) for a more comprehensive guide.

### 1. Install
Install by adding the bintray repository and the dependency.

```groovy
// Top level build file
repositories {
    maven {
        url  "https://dl.bintray.com/terl/lazysodium-maven"
    }
}

// Add to dependencies section
dependencies {
    implementation "com.goterl.lazycode:lazysodium-java:VERSION_NUMBER"
}
```

Substitute `VERSION_NUMBER` for the version in this box:

[![Download](https://api.bintray.com/packages/terl/lazysodium-maven/lazysodium-java/images/download.svg) ](https://bintray.com/terl/lazysodium-maven/lazysodium-java/_latestVersion)

### 2. Let's go!

You can now initialise and start encrypting! **Please note** that this library follows the official [libsodium docs](https://download.libsodium.org/doc/) closely. You need to use those docs to help you find the functions you need.

```java
// Let's initialise LazySodium
LazySodiumJava lazySodium = new LazySodiumJava(new SodiumJava());

// Now you can cast to an interface so that our
// IDE picks up and intelligently loads up the correct methods. 
SecretBox.Native secretBoxNative = (SecretBox.Native) lazySodium;
SecretBox.Lazy secretBoxLazy = (SecretBox.Lazy) lazySodium;

// The first one is Lazysodium's Native implementation which
// is just like libsodium's native C function but with tiny enhancements
// to make your life easier.
secretBoxNative.cryptoSecretBoxKeygen(key);
// Convert key to string and save to DB

// This one is Lazysodium's Lazy implementation which makes
// your work with cryptography super easy.
String key = secretBoxLazy.cryptoSecretBoxKeygen();
```

In the above code there are two ways you can use Lazysodium. The first way is through the Native interface. The second is through the Lazy interface. 

Every project is different, you may need to use lower-level APIs to achieve the control you need so you use the Native interface. Or alternatively you just don't want to deal with the details so you stick to the Lazy interface.

Every interface you can cast to is helpfully all in one directory so you can easily pick the functions you need. This isolates your code and prevents you from making mistakes.

**Important:** If possible, please stick to using either the Native *or* the Lazy interface. The reason for this is that the Lazy interface normally converts everything to hexadecimal whereas the Native interface assumes everything is non-hexadecimal. If you don't know what you're doing, you could end up making mistakes.


## Documentation

See our [official documentation](https://docs.lazycode.co/lazysodium) to get started.


## Lazysodium for Android
We also have an Android implementation available at [Lazysodium for Android](https://github.com/terl/lazysodium-android). It has the same API as this library so you can share code easily!

<br>
<br>

<a href="https://terl.co"><img width="100" style="float: left: display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/terl_slant.png" /></a>

Created by the wizards at [Terl](https://terl.co).
