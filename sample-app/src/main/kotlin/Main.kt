import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.goterl.lazysodium.exceptions.SodiumException
import com.goterl.lazysodium.interfaces.*
import com.goterl.lazysodium.utils.Key
import com.goterl.lazysodium.utils.KeyPair
import com.goterl.lazysodium.utils.LibraryLoader
import com.sun.jna.NativeLong
import org.fusesource.jansi.Ansi
import org.fusesource.jansi.Ansi.ansi
import org.fusesource.jansi.AnsiConsole


class Main(private val parsed: Int) {

    private val lazySodium = LazySodiumJava(SodiumJava(LibraryLoader.Mode.BUNDLED_ONLY))

    fun run() {
        try {
            if (parsed == 1) {
                symmetricKeyEncryptionStep1()
            }
            if (parsed == 2) {
                publicPrivateKeyEncryptionStep1()
            }
            if (parsed == 3) {
                genericHashStep1()
                genericHashStep1b()
                genericHashStep2()
            }
            if (parsed == 4) {
                pwHashStep1()
            }
            if (parsed == 5) {
                sign()
                signWithNonRandomKeys()
            }
        } catch (e: SodiumException) {
            e.printStackTrace()
        }
    }

    @Throws(SodiumException::class)
    private fun sign() {
        printSection("Running sign detached")
        val msg = "This message needs to be signed"
        val kp: KeyPair = lazySodium.cryptoSignKeypair()
        val pk: Key = kp.publicKey
        val sk: Key = kp.secretKey
        if (!lazySodium.cryptoSignKeypair(pk.asBytes, sk.asBytes)) {
            throw SodiumException("Could not generate a signing keypair.")
        }
        printStep(
            "1",
            "Signing a message",
            "We will be using the random secret key '" + sk.asHexString.toString() + "' and will be " +
                    "signing the message '" + msg + "'."
        )
        val messageBytes: ByteArray = lazySodium.bytes(msg)
        val skBytes: ByteArray = sk.asBytes
        val signatureBytes = ByteArray(Sign.BYTES)
        lazySodium.cryptoSignDetached(signatureBytes, messageBytes, messageBytes.size.toLong(), skBytes)
        val v: Boolean =
            lazySodium.cryptoSignVerifyDetached(signatureBytes, messageBytes, messageBytes.size, pk.getAsBytes())
        log()
        logt("The signed message is " + LazySodium.toHex(signatureBytes) + ".")
        logt("Verifying the signed message outputs true: $v.")
    }

    @Throws(SodiumException::class)
    private fun signWithNonRandomKeys() {
        val msg = "Sign this"
        val pk: Key = Key.fromPlainString("edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav8888888888")
        val sk: Key = Key.fromPlainString("edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh8888888888")
        log()
        printStep(
            "2",
            "Signing a message (non-random)",
            ("We will be using the non-random secret key '" + sk.asHexString.toString() + "' and will be " +
                    "signing the message '" + msg + "'.")
        )
        if (!lazySodium.cryptoSignKeypair(pk.asBytes, sk.asBytes)) {
            throw SodiumException("Could not generate a signing keypair.")
        }
        val signed: String = lazySodium.cryptoSignDetached(msg, sk)
        val verification: Boolean = lazySodium.cryptoSignVerifyDetached(signed, msg, pk)
        log()
        logt("The signed message is $signed.")
        logt("Verifying the signed message outputs true: $verification.")
    }

    @Throws(SodiumException::class)
    private fun symmetricKeyEncryptionStep1() {
        printSection("Running symmetric key encryption")
        val key: Key = lazySodium.cryptoSecretBoxKeygen()
        val msg = "This message needs top security"
        printStep(
            "1",
            "Encrypting a message with a symmetric key",
            ("We will be using the random key '" + key.getAsHexString().toString() + "' and will be " +
                    "encrypting the message '" + msg + "'.")
        )
        val nonce: ByteArray = lazySodium.nonce(SecretBox.NONCEBYTES)
        val encrypted: String = lazySodium.cryptoSecretBoxEasy(msg, nonce, key)
        log()
        logt("The encrypted string is $encrypted.")
        logt("You should also store the nonce " + lazySodium.toHexStr(nonce) + ".")
        logt("The nonce can be stored in a public location.")
        symmetricKeyEncryptionStep2(key, nonce, encrypted)
    }

    @Throws(SodiumException::class)
    private fun symmetricKeyEncryptionStep2(key: Key, nonce: ByteArray, encrypted: String) {
        log()
        printStep(
            "2",
            "Decrypting a message with a symmetric key",
            "We will now decrypt the message we encrypted in the previous step."
        )
        val decrypted: String = lazySodium.cryptoSecretBoxOpenEasy(encrypted, nonce, key)
        log()
        logt("The decrypted string is $decrypted.")
        logt("It should equal the message we encrypted in step 1.")
    }

    @Throws(SodiumException::class)
    private fun publicPrivateKeyEncryptionStep1() {
        printSection("Running public private key encryption")
        log()
        printStep(
            "1",
            "Generating public private keypairs",
            "In this step we'll generate public keys for Alice " +
                    "and Bob."
        )
        val aliceKp: KeyPair = lazySodium.cryptoBoxKeypair()
        val bobKp: KeyPair = lazySodium.cryptoBoxKeypair()
        log()
        logt("Alice's public key: " + aliceKp.publicKey.asHexString)
        logt("Bob's public key: " + bobKp.publicKey.asHexString)
        log()
        publicPrivateKeyEncryptionStep2(aliceKp, bobKp)
    }

    @Throws(SodiumException::class)
    private fun publicPrivateKeyEncryptionStep2(aliceKp: KeyPair, bobKp: KeyPair) {
        val message = "Cryptography is the best"
        printStep(
            "2",
            "Encrypting a message with a public private keypair",
            "Alice wants to send the message '$message' to Bob."
        )

        // Make sure that we provide the secret key of Alice encrypting
        // the message using Bob's public key.
        val aliceToBobKp = KeyPair(bobKp.publicKey, aliceKp.secretKey)
        val nonce: ByteArray = lazySodium.nonce(Box.NONCEBYTES)
        val encrypted: String = lazySodium.cryptoBoxEasy(message, nonce, aliceToBobKp)
        log()
        logt("Alice uses her private key to encrypt the message with Bob's public key.")
        logt("Encryption result: $encrypted")
        log()
        publicPrivateKeyEncryptionStep3(encrypted, nonce, aliceKp, bobKp)
    }

    @Throws(SodiumException::class)
    private fun publicPrivateKeyEncryptionStep3(encrypted: String, nonce: ByteArray, aliceKp: KeyPair, bobKp: KeyPair) {

        // Make sure we have Bob's private key decrypting the message with
        // Alice's public key.
        val bobFromAliceKp = KeyPair(aliceKp.getPublicKey(), bobKp.getSecretKey())
        val decrypted: String = lazySodium.cryptoBoxOpenEasy(encrypted, nonce, bobFromAliceKp)
        logt("Bob uses his private key to decrypt the message.")
        logt("Decryption result: '$decrypted'.")
        log()
    }

    @Throws(SodiumException::class)
    private fun genericHashStep1() {
        printSection("Running generic hash")

        // We can generate a random key or
        // we can provide a key.
        // String randomKey = lazySodium.cryptoGenericHashKeygen();

        // Key must be larger than GenericHash.KEYBYTES_MIN
        // but less than GenericHash.KEYBYTES_MAX
        val key = "randomkeyoflength16bytes"
        printStep(
            "1",
            "Deterministic key hash",
            "The following hashes should be the same as we're using " +
                    "identical keys for them.",
            "We will be using the key '$key'."
        )
        val hash: String = lazySodium.cryptoGenericHash("", Key.fromPlainString(key))
        val hash2: String = lazySodium.cryptoGenericHash("", Key.fromPlainString(key))
        log()
        logt("Hash 1: $hash")
        logt("Hash 2: $hash2")
        logt("Hash 1 == Hash 2? " + hash.equals(hash2, ignoreCase = true))
        log()
    }

    private fun printSection(sectionTitle: String) {
        log(" ")
        log(" >>> $sectionTitle.")
        log(" ")
    }

    private fun printStep(step: String, title: String, vararg descriptions: String) {
        log("+ Step $step: $title.")
        for (desc: String in descriptions) {
            log("  $desc")
        }
    }

    @Throws(SodiumException::class)
    private fun genericHashStep1b() {
        val randomKey: ByteArray = lazySodium.randomBytesBuf(GenericHash.KEYBYTES)
        printStep(
            "1b",
            "Deterministic key hash using Native",
            "The following hashes should be the same as we're using " +
                    "identical keys for them.",
            "We will be using the random key '" + lazySodium.toHexStr(randomKey) + "'."
        )
        val nativeGH: com.goterl.lazysodium.interfaces.GenericHash.Native =
            lazySodium as com.goterl.lazysodium.interfaces.GenericHash.Native
        val message: ByteArray = lazySodium.bytes("Top secret message.")
        val hash: ByteArray = lazySodium.randomBytesBuf(GenericHash.BYTES)
        val hash2: ByteArray = lazySodium.randomBytesBuf(GenericHash.BYTES)
        val res: Boolean =
            nativeGH.cryptoGenericHash(hash, hash.size, message, message.size.toLong(), randomKey, randomKey.size)
        val res2: Boolean =
            nativeGH.cryptoGenericHash(hash2, hash2.size, message, message.size.toLong(), randomKey, randomKey.size)
        if (!res || !res2) {
            throw SodiumException("Could not hash the message.")
        }
        val hash1Hex: String = lazySodium.toHexStr(hash)
        val hash2Hex: String = lazySodium.toHexStr(hash2)
        log()
        logt("Hash 1: $hash1Hex")
        logt("Hash 2: $hash2Hex")
        logt("Hash 1 == Hash 2? " + hash1Hex.equals(hash2Hex, ignoreCase = true))
        log()
    }

    @Throws(SodiumException::class)
    private fun genericHashStep2() {
        log("+ Step 2: Random key hash.")
        log(
            "  The following hashes should be different as we're using" +
                    " random keys for them."
        )
        val hashRandom: String = lazySodium.cryptoGenericHash("", lazySodium.cryptoGenericHashKeygen())
        val hashRandom2: String = lazySodium.cryptoGenericHash("", lazySodium.cryptoGenericHashKeygen())
        log()
        logt("Hash 1: $hashRandom")
        logt("Hash 2: $hashRandom2")
        logt("Hash 1 == Hash 2? " + hashRandom.equals(hashRandom2, ignoreCase = true))
        log()
    }

    private fun pwHashStep1() {
        printSection("Running password hashing")
        val pw = "superAwesomePassword"
        printStep(
            "1",
            "Hashing a password",
            "Attempting to hash a password '$pw' using Argon 2."
        )
        try {
            val hash: String = lazySodium.cryptoPwHashStr(pw, 2L, NativeLong(65536))
            log()
            logt("Password hashing successful: $hash")
            log()
        } catch (e: SodiumException) {
            e.printStackTrace()
            log()
            logt("Password hashing failed with exception: " + e.message)
            log()
        }
        pwHashStep2()
    }

    private fun pwHashStep2() {
        val pw = "lol"
        printStep(
            "2",
            "Multiple password verification (Native)",
            ("Verifying password '" + pw + "' using Argon2 many times. " +
                    "This may take a while...")
        )
        val pwBytes: ByteArray = lazySodium.bytes(pw)

        // Remember the terminating byte (null byte) at the end of the hash!
        // As this is using the Native interface you must always remember
        // to add that null byte yourself. Use the Lazy interface if you
        // don't want to handle any of that (as shown in the next step).
        val hash: ByteArray = lazySodium.bytes(
            "\$argon2id\$v=19\$m=65536,t=2,p=1\$ZrWMVZiMs4tvs0QwVc7T7A\$L" +
                    "Il6XlgIZsuozRpC3bCe5ew8LEWgDQvQE8qwsZ9ISps\u0000"
        )
        log()
        var i = 0
        while (i < 100) {
            val result: Boolean = lazySodium.cryptoPwHashStrVerify(hash, pwBytes, pwBytes.size)
            logt("Password hashing verification: $result")
            i++
        }
        log()
        pwHashStep3()
    }

    private fun pwHashStep3() {
        val pw = "password"
        printStep(
            "2",
            "Multiple password hashing (Lazy)",
            ("Hashing password '" + pw + "' using Argon2 lazy methods. " +
                    "This also may take a while...")
        )
        log()
        var i = 0

        // In the following while loop, we keep hashing the above password
        // then we verify it. If at any point we aren't successful we log it.
        while (i < 30) {
            try {
                // You can also remove the null bytes at the end of this hex hash
                // using cryptoPwHashStrRemoveNulls instead of
                // cryptoPwHashStr, but that is not recommended
                // as Argon2 needs at least one null byte
                // at the end.
                val hash: String = lazySodium.cryptoPwHashStr(pw, 2, PwHash.MEMLIMIT_MIN)

                // To get an Argon2 hash instead of a hex hash,
                // lazySodium.str(lazySodium.toBinary(hash)) is one way to do that.
                logt("Password hashing successful: $hash")
                val result: Boolean = lazySodium.cryptoPwHashStrVerify(hash, pw)
                logt("Password hashing verification: $result")
            } catch (e: SodiumException) {
                logt("Password hashing unsuccessful: " + e.message)
            }
            i++
        }
        log()
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            // First setup
            setup()
            printTitle()
            if (args.size == 0) {
                printIntro()
            } else {
                // Run only if provided an argument
                val arg1 = args[0]
                try {
                    val parsed = arg1.toInt()
                    val main = Main(parsed)
                    main.run()
                } catch (e: NumberFormatException) {
                    AnsiConsole.system_err.println(
                        ("Error: " + arg1 + " is not a valid number. " +
                                "Please provide a number of the operation you want to perform.")
                    )
                }
            }
        }

        private fun setup() {
            AnsiConsole.systemInstall()
        }

        private fun printTitle() {
            val line: Ansi = ansi()
                .fgBrightRed()
                .a(" ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                .reset()
            log()
            log(line)
            log("      Lazysodium for Java (Examples)       ")
            log(line)
            log()
        }

        private fun printIntro() {
            log("Please provide, as a command line argument, one of the following numbers:")
            log("1. Secret key: Perform encryption using a symmetric key.")
            log("2. Public key: Encryption using public-private key.")
            log("3. Generic hashing: Hash arbitrarily.")
            log("4. Password hashing: Password hash.")
            log("5. Sign (detached): Sign a message in detached mode.")
            log()
        }

        // Helpers
        private fun log(s: String = "") {
            println(s)
        }

        private fun logt(s: String) {
            println("\t" + s)
        }

        private fun log(s: Ansi) {
            AnsiConsole.out().println(s)
        }
    }

}