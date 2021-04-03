<p align="center"><img width="260" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/lazysodium_large_transparent.png" /></p>

# Lazysodium for Java

Lazysodium is a **complete** Java (JNA) wrapper over the [Libsodium](https://github.com/jedisct1/libsodium) library that provides developers with a **smooth and effortless** cryptography experience.

![Checks](https://github.com/terl/lazysodium-java/actions/workflows/primary.yml/badge.svg)
![Maven Central](https://img.shields.io/maven-central/v/com.goterl/lazysodium-java?color=%23fff&label=Maven%20Central)

## Features

**This library is fully compatible with Kotlin.**

You can find an up-to-date feature list [here](https://terl.gitbook.io/lazysodium/about-1/features).

## Quick start
Please view the [official documentation](https://terl.gitbook.io/lazysodium/usage/installation) for a more comprehensive guide.

### 1. Install
Whatever build tool you're using the general gist is to add the `mavenCentral()` repository and then add the Lazysodium dependency. 
More detailed instructions [here](https://terl.gitbook.io/lazysodium/usage/installation).

The following example is for users of the build tool Gradle:

```groovy
// Top level build file
repositories {
    // Add this to the end of any existing repositories
    mavenCentral() 
}

// Project level dependencies section
dependencies {
    implementation "com.goterl:lazysodium-java:VERSION_NUMBER"
    implementation "net.java.dev.jna:jna:JNA_NUMBER"
}
```

Substitute `VERSION_NUMBER` for the version in this box:

![Maven Central](https://img.shields.io/maven-central/v/com.goterl/lazysodium-java?color=%23fff&label=Maven%20Central)

Substitute `JNA_NUMBER` for the [latest version of JNA](https://github.com/java-native-access/jna/releases).

### 2. Usage

You can now use the library. **Please note** that this library follows the official [libsodium docs](https://download.libsodium.org/doc/) closely. You need to use those docs to help you find the functions you need.

```java
// Let's initialise LazySodium
LazySodiumJava lazySodium = new LazySodiumJava(new SodiumJava());

// Here's an example of hashing a password.
// Casting the lazySodium object is optional, 
// but it's wise to do so as it prevents accidents.
PwHash.Lazy pwHashLazy = (PwHash.Lazy) lazySodium;
String hash = pwHashLazy.cryptoPwHashStr("a cool password", PwHash.OPSLIMIT_MIN, PwHash.MEMLIMIT_MIN);
```

You can use the `Native` or `Lazy` interfaces to encrypt at a lower or a higher level. It's all very simple.

**Important:** If possible, please stick to using either the Native *or* the Lazy interface. The reason for this is that the Lazy interface normally converts everything to hexadecimal whereas the Native interface assumes everything is non-hexadecimal. If you don't know what you're doing, you could end up making mistakes.


## Documentation

Please view our [official documentation](https://terl.gitbook.io/lazysodium/) to get started.


## Examples
There are some example projects available [here](https://github.com/terl/lazysodium-examples).


## Used by

| **Name** | **Short description** | 
| :--- | :--- | 
| [**WordPress**](https://apps.wordpress.com/mobile/) | WordPress, one of the largest website builders, has Lazysodium powering their encryption in their Android app. |
| [**Dailymotion Kinta**](https://github.com/dailymotion/kinta) | Dailymotion Kinta, end-to-end automation for mobiles |
| [**Threema \(SaltyRTC\)**](https://github.com/saltyrtc/saltyrtc-client-java) | Threema is a global end-to-end encrypted chatting app and _SaltyRTC_ is their protocol for encryption. |
| [**OpenHAB**](https://github.com/openhab/openhab-osgiify) | [OpenHAB](https://www.openhab.org/) allows you to automate and superpower your home. |
| [**PayPay**](https://github.com/paypayue/AndroidPaymentSDK) | CardPaymentSDK is a card payments library to make payments through several payment methods painless. It uses [PayPay](https://paypay.pt/paypay/) as an endpoint to establish a payment security channel. | 
| [**UXBOX**](https://github.com/uxbox/uxbox) | UXBox, the open-source solution for design and prototyping |
| [**E3DB**](https://tozny.com/e3db/) | An encrypted NoSQL database designed from the ground-up for user privacy and security. | 
| [**ADAMANT**](https://adamant.im/) | The most private messenger possible. Your device does not store any info. It directly interacts with the blockchain, where every byte is fully-encrypted. | 
| [**Kepler**](https://github.com/Quackster/Kepler) | A small TCP server written in Java powered by Netty, an asynchronous networking library. |
| [**Regen Ledger**](https://www.regen.network/) | A global marketplace & contracting platform for Earth's ecosystem assets, services, and data. |
| [**Tezos**](https://github.com/LMilfont/TezosJ-plainjava) | The TezosJ SDK library enables plain Java developers to create applications that communicates with Tezos blockchain. |
| [**Exonum**](https://github.com/exonum/exonum-java-binding) | Exonum Java Binding is a framework for building blockchain applications in Java, powered by Exonum. |
| [**Paseto**](https://github.com/atholbro/paseto) | Java Implementation of Platform-Agnostic Security Tokens. |
| [**Recordo**](https://recordo.co) | A super secure diary/journal that provides end to end encryption. |


## Lazysodium for Android
We also have an Android implementation available at [Lazysodium for Android](https://github.com/terl/lazysodium-android). It has the same API as this library so you can share code easily!

You can preview some of the features in our free Lazysodium app available on Google Play:

<a href='https://play.google.com/store/apps/details?id=com.goterl.lazycode.lazysodium.example&pcampaignid=MKT-Other-global-all-co-prtnr-py-PartBadge-Mar2515-1'><img alt='Get it on Google Play' src='https://play.google.com/intl/en_gb/badges/images/generic/en_badge_web_generic.png' width="140"/></a>


---

<a href="https://terl.co"><img width="100" style="float: left: display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/terl.png" /></a>

Created by [Terl](https://terl.co).
