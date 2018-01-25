package org.mypico.jpico.test.visualcode;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;
import org.mypico.jpico.test.gson.VisualCodeGsonTest;

@RunWith(Suite.class)
@SuiteClasses({NewKeyVisualCodeTest.class, KeyPairingVisualCodeTest.class,
        VisualCodeGsonTest.class})
public class VisualCodeTestSuite {

}
