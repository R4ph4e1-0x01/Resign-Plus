package custom.util;


import burp.IRequestInfo;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public interface IHttpReqRespUtil {

    static final byte PARAM_HEADER = 10;

    LinkedHashMap<String, String> headersMap = new LinkedHashMap<>();
    LinkedHashMap<String, String> paraMap = new LinkedHashMap<>();

}
