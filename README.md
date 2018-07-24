
<br />

<p align="center"><img width="260" style="float: center;" style="display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/lazycode/lazysodium/large_logo.png" /></p>

<br />


# Lazysodium for Java

Lazysodium is a **complete** Java (JNA) wrapper over the [Libsodium](https://github.com/jedisct1/libsodium) library that provides developers with a **smooth and effortless** cryptography experience.


[![Build Status](https://semaphoreci.com/api/v1/terl/lazysodium-java/branches/master/badge.svg)](https://semaphoreci.com/terl/lazysodium-java)
[![Download](https://api.bintray.com/packages/terl/lazysodium-maven/lazysodium-java/images/download.svg) ](https://bintray.com/terl/lazysodium-maven/lazysodium-java/_latestVersion)

## Why Lazysodium
We created Lazysodium because we really wanted a solid cryptography library that would just work without fuss.

We were exasperated and annoyed with current Libsodium implementations as some of them were just poorly maintained, poorly managed and, plain and simply, poorly architected. Thus, Lazysodium was born with the blessings of *Lazycode*, a part of [Terl](https://terl.co) that specialises in giving developers easy-to-use software and tools that just work.

You can find more info [here](https://docs.lazycode.co/lazysodium/about).


## Features
You can find an up-to-date feature list [here](https://docs.lazycode.co/lazysodium/features).


## Quick start
Please view the [official documentation](https://docs.lazycode.co/lazysodium/installation) for a more comprehensive guide.

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
    implementation "net.java.dev.jna:jna:JNA_VERSION"
}
```

Substitute `VERSION_NUMBER` for the version in this box:

[![Download](https://api.bintray.com/packages/terl/lazysodium-maven/lazysodium-java/images/download.svg) ](https://bintray.com/terl/lazysodium-maven/lazysodium-java/_latestVersion)

Substitute `JNA_VERSION` for the [latest JNA version](https://mvnrepository.com/artifact/net.java.dev.jna/jna).

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
Key key = secretBoxLazy.cryptoSecretBoxKeygen();
```

In the above code there are two ways you can use Lazysodium. The first way is through the Native interface. The second is through the Lazy interface. 

### 3. You decide

Every project is different, you may need to use lower-level APIs to achieve the control you need so you use the `Native` interface. Or alternatively you just don't want to deal with the details so you stick to the `Lazy` interface.

Every interface you can cast to is helpfully all in [one directory](https://github.com/terl/lazysodium-java/tree/master/src/main/java/com/goterl/lazycode/lazysodium/interfaces) so you can easily pick the functions you need. This isolates your code and prevents you from making mistakes.

**Important:** If possible, please stick to using either the Native *or* the Lazy interface. The reason for this is that the Lazy interface normally converts everything to hexadecimal whereas the Native interface assumes everything is non-hexadecimal. If you don't know what you're doing, you could end up making mistakes.


## Documentation

See our [official documentation](https://docs.lazycode.co/lazysodium) to get started.


## Examples
There are some example projects available [here](https://github.com/terl/lazysodium-examples).


## Lazysodium for Android
We also have an Android implementation available at [Lazysodium for Android](https://github.com/terl/lazysodium-android). It has the same API as this library so you can share code easily!

You can preview some of the features in our free Lazysodium app available on Google Play:

<a href='https://play.google.com/store/apps/details?id=com.goterl.lazycode.lazysodium.example&pcampaignid=MKT-Other-global-all-co-prtnr-py-PartBadge-Mar2515-1'><img alt='Get it on Google Play' src='https://play.google.com/intl/en_gb/badges/images/generic/en_badge_web_generic.png' width="140"/></a>



## Help us grow
Lazysodium needs your support for it to continue being maintained and improved. Even if you put forward £1/$1/€1 it still means a lot for us. Your money would go into improving our open-source projects first and foremost. If you want to find out more, use your preffered donation platform. 


|  |Patreon       | Liberapay      | Terl Supporters |
|----|--------------|---------------------|---|
|    | <a href="https://www.patreon.com/terlacious"><img src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/patron_button.png" width="100" /></a> | <a href="https://liberapay.com/terlacious/"><img src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/liberapay.png" width="40" /></a> | <a href="https://terl.co/support-us"><img src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/terl_slant_square.png" width="40" /></a> |
|  One-time  | ✗ | ✗ | ✓ |
|  Weekly  | ✗ | ✓ | ✓ |
|  Monthly  | ✓ | ✓ | ✓ |
|  Yearly  | ✗ | ✓ | ✓ |
|  Rewards  | ✓ | ✗ | ✓ |
|  Currencies  | USD | USD, EUR | 100+ currencies |


Patreon only has recurring subscriptions and rewards. Liberapay is another route you could take for subscription. We're also setting up our own system that allows one-off support amongst other things.


## Who are we?

<a href="https://terl.co"><img width="100" style="float: left: display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/terl_slant.png" /></a>

Created by the wizards at [Terl](https://terl.co).
