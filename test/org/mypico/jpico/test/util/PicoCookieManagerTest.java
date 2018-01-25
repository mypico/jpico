package org.mypico.jpico.test.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.mypico.jpico.crypto.Cookie;
import org.mypico.jpico.util.PicoCookieManager;

import com.google.common.collect.Lists;

public class PicoCookieManagerTest {
	@Test
    public void testPicoCookieManager() {
		try {
			PicoCookieManager manager = new PicoCookieManager();
			Map<String, List<String>> map = new HashMap<String, List<String>>();
			map.put("Server", Lists.newArrayList("Github.com"));
			map.put("Set-Cookie", Lists.newArrayList("user_session=5O0aVe0qRmOxUjv55aW1; path=/; expires=Wed, 30 Aug 2017 10:59:52 -0000"));
			map.put("Date", Lists.newArrayList("Wed, 16 Aug 2017 10:59:52 GMT"));
			manager.put(new URI("http://github.com"), map);
			
			List<Cookie> capturedCookies = manager.getRawCookies();
			
			assertEquals(capturedCookies.size(), 1);
			Cookie c = capturedCookies.get(0);
			assertEquals(c.toString(), "Url:http://github.com Value:user_session=5O0aVe0qRmOxUjv55aW1; path=/; expires=Wed, 30 Aug 2017 10:59:52 -0000 Date:Wed, 16 Aug 2017 10:59:52 GMT");
			
			
		} catch (Exception e) {
			fail();
		}
	}
}
