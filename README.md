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

## Installation, documentation, FAQ and everything else

See our [official documentation](https://docs.lazycode.co/lazysodium) to get started.


<br>
<br>

<a href="https://terl.co"><img width="100" style="float: left: display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/terl_slant.png" /></a>

Created by the wizards at [Terl](https://terl.co).

