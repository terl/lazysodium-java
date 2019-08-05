
/*
 * Copyright (c) Terl Tech Ltd • 14/06/19 17:54 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.utils;

import com.goterl.lazycode.lazysodium.Sodium;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.utils.LibraryLoader.JnaLoader;
import org.junit.Test;
import org.mockito.AdditionalMatchers;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;

import static com.goterl.lazycode.lazysodium.utils.LibraryLoader.Mode.*;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class LibraryLoaderTest {

  @Test
  public void testOneOffLoadingFromPath() {
    String sodiumPath = "/tmp/test/libsodium.so";
    JnaLoader jnaLoader = mock(JnaLoader.class);
    LibraryLoader libLoader = new LibraryLoader(jnaLoader);

    libLoader.loadLibrary(sodiumPath);

    verifyLoadedOnce(jnaLoader, sodiumPath);
  }

  @Test
  public void testOneOffLoadingFromJar() {
    JnaLoader jnaLoader = mock(JnaLoader.class);
    LibraryLoader libLoader = new LibraryLoader(jnaLoader);

    // This test relies on the given placement of libsodium.so for linux in the resources.
    // As it does not actually load it, the platform does not matter — but the mere
    // presence of the file in the resources.
    libLoader.loadLibrary(BUNDLED_ONLY);

    verifyLoadedFromJarOnce(jnaLoader);
  }

  @Test
  public void testLoadingOnSecondAttempt() {
    String path1 = "/tmp/test/libsodium.so";
    JnaLoader jnaLoader = mock(JnaLoader.class);
    doThrow(IllegalArgumentException.class)
        .when(jnaLoader).register(any(Class.class), eq(path1));

    LibraryLoader libLoader = new LibraryLoader(jnaLoader);

    // First attempt, failing
    try {
      libLoader.loadLibrary(path1);
      fail("^ must throw, but didn't");
    } catch (IllegalArgumentException expected) {
      verify(jnaLoader, atLeastOnce())
          .register(any(Class.class), eq(path1));
    }

    // Second attempt, must be successful
    String path2 = "./libsodium.so";
    libLoader.loadLibrary(path2);
    verifyLoadedOnce(jnaLoader, path2);
  }

  @Test
  public void testSequentialLoadingWillOnlyLoadOnce() {
    String sodiumPath = "/tmp/test/libsodium.so";
    JnaLoader jnaLoader = mock(JnaLoader.class);
    LibraryLoader libLoader = new LibraryLoader(jnaLoader);
    int numAttempts = 32;
    for (int i = 0; i < numAttempts; i++) {
      libLoader.loadLibrary(sodiumPath);
    }
    verifyLoadedOnce(jnaLoader, sodiumPath);
  }

  @Test
  public void testConcurrentLoading() throws Exception {
    // Make several attempts to increase the confidence of thread collision
    int numAttempts = 100;
    for (int i = 0; i < numAttempts; i++) {
      testConcurrentLoadingOnce();
    }
  }

  private void testConcurrentLoadingOnce() throws InterruptedException {
    // Number of threads to attempt concurrent loading
    int numThreads = 32;
    List<Thread> threads = new ArrayList<>(numThreads);
    CyclicBarrier startBarrier = new CyclicBarrier(numThreads);

    String sodiumPath = "/tmp/test/libsodium.so";
    JnaLoader jnaLoader = mock(JnaLoader.class);
    LibraryLoader libLoader = new LibraryLoader(jnaLoader);
    for (int i = 0; i < numThreads; i++) {
      threads.add(new Thread(
          () -> {
            try {
              startBarrier.await();
              libLoader.loadLibrary(sodiumPath);
            } catch (InterruptedException e) {
              // Just return
            } catch (BrokenBarrierException e) {
              e.printStackTrace();
            }
          }
      ));
    }

    // Start the test
    threads.forEach(Thread::start);

    // Wait for completion
    for (Thread t : threads) {
      try {
        t.join();
      } catch (InterruptedException e) {
        threads.forEach(Thread::interrupt);
        throw e;
      }
    }

    // Verify the loader was invoked exactly once
    verifyLoadedOnce(jnaLoader, sodiumPath);
  }

  @Test
  public void testLoadingSystemWhenPresent() {
    JnaLoader jnaLoader = mock(JnaLoader.class);
    LibraryLoader libLoader = new LibraryLoader(jnaLoader);

    // Try to load
    libLoader.loadLibrary(PREFER_SYSTEM);

    // Check the library was loaded
    verifyLoadedOnce(jnaLoader, "sodium");
  }

  @Test
  public void testLoadingSystemWhenAbsent() {
    JnaLoader jnaLoader = mock(JnaLoader.class);
    LibraryLoader libLoader = new LibraryLoader(jnaLoader);
    doThrow(UnsatisfiedLinkError.class).when(jnaLoader)
            .register(Sodium.class, "sodium");

    // Try to load
    libLoader.loadLibrary(PREFER_SYSTEM);

    // Check the library was loaded
    // First unsuccessful attempt
    verify(jnaLoader).register(eq(Sodium.class), eq("sodium"));

    // Subsequent attempts from JAR
    verify(jnaLoader).register(eq(Sodium.class), AdditionalMatchers.not(eq("sodium")));
    verify(jnaLoader).register(eq(SodiumJava.class), anyString());
  }

  @Test
  public void testLoadingSystemOnlyWhenPresent() {
    JnaLoader jnaLoader = mock(JnaLoader.class);
    LibraryLoader libLoader = new LibraryLoader(jnaLoader);

    // Try to load
    libLoader.loadLibrary(SYSTEM_ONLY);

    // Check the library was loaded
    verifyLoadedOnce(jnaLoader, "sodium");
  }

  @Test
  public void testLoadingSystemOnlyWhenAbsent() {
    JnaLoader jnaLoader = mock(JnaLoader.class);
    LibraryLoader libLoader = new LibraryLoader(jnaLoader);
    // JNA throws if no system sodium installed
    doThrow(UnsatisfiedLinkError.class).when(jnaLoader)
            .register(Sodium.class, "sodium");

    // Try to load
    try {
      libLoader.loadLibrary(SYSTEM_ONLY);
      fail("Must throw");
    } catch (LibraryLoadingException expected) {
      // Pass
    }
  }

  private static void verifyLoadedOnce(JnaLoader jnaLoaderMock, String sodiumPath) {
    verify(jnaLoaderMock).register(Sodium.class, sodiumPath);
    verify(jnaLoaderMock).register(SodiumJava.class, sodiumPath);
    verifyNoMoreInteractions(jnaLoaderMock);
  }

  private static void verifyLoadedFromJarOnce(JnaLoader jnaLoaderMock) {
    verify(jnaLoaderMock).register(eq(Sodium.class), anyString());
    verify(jnaLoaderMock).register(eq(SodiumJava.class), anyString());
    verifyNoMoreInteractions(jnaLoaderMock);
  }

  @Test
  public void createsTempDirectory() throws IOException {
    File dir = LibraryLoader.createTempDirectory();

    assertTrue(dir.toString(), dir.exists());
  }

  @Test
  public void createsNonUniqueTempDirectory() throws IOException {
    File firstDir = LibraryLoader.createTempDirectory();
    File secondDir = LibraryLoader.createTempDirectory();

    assertThat(firstDir, equalTo(secondDir));
  }
}
