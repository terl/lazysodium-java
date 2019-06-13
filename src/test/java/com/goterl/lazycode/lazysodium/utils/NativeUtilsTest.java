package com.goterl.lazycode.lazysodium.utils;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import org.junit.Test;

public class NativeUtilsTest {

  @Test
  public void createsTempDirectory() throws IOException {
    File dir = NativeUtils.createTempDirectory();

    assertTrue(dir.toString(), dir.exists());
  }

  @Test
  public void createsUniqueTempDirectory() throws IOException {
    File firstDir = NativeUtils.createTempDirectory();
    File secondDir = NativeUtils.createTempDirectory();

    assertThat(firstDir, not(equalTo(secondDir)));
  }
}
