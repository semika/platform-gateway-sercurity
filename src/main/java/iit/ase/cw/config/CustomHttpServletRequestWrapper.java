package iit.ase.cw.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.util.HashMap;
import java.util.Map;

public class CustomHttpServletRequestWrapper extends HttpServletRequestWrapper {

    private Map customHeaderMap = null;

    public CustomHttpServletRequestWrapper(HttpServletRequest request) {
        super(request);
        customHeaderMap = new HashMap();
    }

    public void addHeader(String name,String value){
        customHeaderMap.put(name, value);
    }
}
