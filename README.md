
# Lazysodium for Java


Lazysodium is a **Java 8+** crypto library that provides a **near complete**  implementation of the [Libsodium](https://github.com/jedisct1/libsodium) library, providing developer's with a **stress-free** and **effortless** experience. 

### Why Lazysodium
We created Lazysodium because we really wanted a solid cryptography library that would just work with as little effort as possible.

We were exasperated and annoyed with current Libsodium implementations as some of them were just poorly maintained, poorly managed and, plain and simply, poorly architected. Getting started with cryptography should not be hard.

Thus, Lazysodium was born with the blessings of *Lazycode*, a part of [Terl](https://terl.co) that specialises in giving developer's easy-to-use software and tools that just work. Read more about us below.


### Requirements
Lazysodium for Java requires:

* JDK 8 or higher.
* Gradle 4.7 or higher (if compiling and building).
* No effort whatsoever.

### Installation

Include Lazysodium in your Java projects using [Maven/Gradle/SBT](#):

```sh
$ implementation "com.goterl.lazycode:lazysodium-java:+"
```


### Documentation and Usage
For the documentation we invite you to head over to the [wiki](https://github.com/terl/lazysodium-java/wiki) for more information on running and building Lazysodium.



### Contributions
All contributions are appreciated and very welcome. There are many forms that contributions could take.

**It could be a simple suggestion.** For example, "*It would be great if Lazysodium implemented feature X.*" If you are suggesting a feature, please make sure it's within the scope of what Lazysodium actually does - which is to wrap Java functions around the native C functions provided by Libsodium.

**It could be that you've found a bug.** Report these immediately on the issue tracker. If it's a very dangerous bug, then confidentiality would be preferred. 

**It could be that you want to contribute code.** Sure, just submit a pull request through GitHub with a short explanation of what you've done.

### Licence
The licence is `MPL v2` as it is a nice middle-ground between copyleft and copyright. I know some developer's would rather not get bogged down in legalities (and we don't blame them). Therefore a brief read of [Mozilla's MPLv2 FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/#apply) will show you the luxuries given to you by the `MPL v2` Licence. Some luxuries include:

* **You can use this library commercially.** 
* You can incorporate this library into other projects (just so long as you don't modify any files - see the point immediately below this one).
* You can modify this library internally within your organisation or company but if you distribute those changes, then you must contribute those changes back to this project or make those changes publicly available.
* The above point fosters a **better community** and so the library is **constantly improved**.