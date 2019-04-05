
package com.github.hisahi.tiralabradesaes;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class MT19937Test {
    
    private MT19937 mt;
    
    @Before
    public void setUp() {
        mt = new MT19937();
    }
    
    /**
     * Some inputs
     */
    @Test
    public void test() {
        mt.setSeed(5489);
        assertEquals(-795755684, mt.nextInt());
        assertEquals(581869302, mt.nextInt());
        assertEquals(-404620562, mt.nextInt());
        assertEquals(-708632711, mt.nextInt());
        assertEquals(545404204, mt.nextInt());
        assertEquals(-133711905, mt.nextInt());
        assertEquals(-372047867, mt.nextInt());
        assertEquals(949333985, mt.nextInt());
        assertEquals(-1579004998, mt.nextInt());
        assertEquals(1323567403, mt.nextInt());
        assertEquals(418932835, mt.nextInt());
        assertEquals(-1944672731, mt.nextInt());
        assertEquals(1196140740, mt.nextInt());
        assertEquals(809094426, mt.nextInt());
        assertEquals(-1946129057, mt.nextInt());
        assertEquals(-30574576, mt.nextInt());
        assertEquals(-182506777, mt.nextInt());
        assertEquals(-15198492, mt.nextInt());
        assertEquals(-150802599, mt.nextInt());
        assertEquals(-138749190, mt.nextInt());
        assertEquals(676943009, mt.nextInt());
        assertEquals(-1177512687, mt.nextInt());
        assertEquals(-126303053, mt.nextInt());
        assertEquals(-81133257, mt.nextInt());
        assertEquals(-183966550, mt.nextInt());
        assertEquals(471852626, mt.nextInt());
        assertEquals(2084672536, mt.nextInt());
        assertEquals(-867128743, mt.nextInt());
        assertEquals(-857788836, mt.nextInt());
        assertEquals(1275731771, mt.nextInt());
        assertEquals(609397212, mt.nextInt());
        assertEquals(20544909, mt.nextInt());
    }
}
