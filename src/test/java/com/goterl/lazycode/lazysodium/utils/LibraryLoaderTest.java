package com.goterl.lazycode.lazysodium.utils;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import com.goterl.lazycode.lazysodium.Sodium;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.utils.LibraryLoader.JnaLoader;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import org.junit.Test;

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
  public void testOneOffLoadingFromJar() throws IOException {
    JnaLoader jnaLoader = mock(JnaLoader.class);
    LibraryLoader libLoader = new LibraryLoader(jnaLoader);

    // This test relies on the given placement of libsodium.so for linux in the resources.
    // As it does not actually load it, the platform does not matter — but the mere
    // presence of the file in the resources.
    libLoader.loadLibraryFromJar("/linux/libsodium.so");

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
  public void createsUniqueTempDirectory() throws IOException {
    File firstDir = LibraryLoader.createTempDirectory();
    File secondDir = LibraryLoader.createTempDirectory();

    assertThat(firstDir, not(equalTo(secondDir)));
  }
}
