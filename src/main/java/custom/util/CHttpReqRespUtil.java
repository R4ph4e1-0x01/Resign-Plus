package custom.util;

import burp.IParameter;
import burp.IRequestInfo;
import custom.util.IHttpReqRespUtil;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class CHttpReqRespUtil implements IHttpReqRespUtil {

//    public static LinkedHashMap<String, String> headersMap = new LinkedHashMap<>();
//    public static LinkedHashMap<String, String> paraMap = new LinkedHashMap<>();

    public static Map<String, String> getHeadersMap(IRequestInfo request){
        List<String> headers = request.getHeaders();
        for (String header:headers){
            if(header.startsWith("GET") ||
                    header.startsWith("POST") ||
                    header.startsWith("PUT")){
                continue;
            }
            String[] h = header.split(": ");
            String headerKey = h[0].trim();
            String headerValue = h[1].trim();
            headersMap.put(headerKey,headerValue);
        }
        return headersMap;
    }

    public static LinkedHashMap<String, String> getHeadersMap(List<String> headers){
        // Process like ""GET / HTTP/1.1""
        for (String header:headers){
            if(header.startsWith("GET") ||
                    header.startsWith("POST") ||
                    header.startsWith("PUT")){
                continue;
            }
            String[] h = header.split(": ");
            String headerKey = h[0].trim();
            String headerValue = h[1].trim();
            headersMap.put(headerKey,headerValue);
        }
        return headersMap;
    }

    public static ArrayList<String> convertHeadersMapToList(Map<String, String> headersMap){
        ArrayList<String> headers = new ArrayList<>();
        for (Map.Entry<String, String> headerEntry : headersMap.entrySet()) {
            String headerName = headerEntry.getKey();
            String headerValue = headerEntry.getValue();
            headers.add(headerName + ": " +headerValue);
        }
        return headers;
    }

    /**以map形式获取参数顺序和列表**/
    public static Map<String, String> getParaMap(IRequestInfo analyzeRequest){
        List<IParameter> paras = analyzeRequest.getParameters();//当body是json格式的时候，这个方法也可以正常获取到键值对，牛掰。但是PARAM_JSON等格式不能通过updateParameter方法来更新。
        for (IParameter para:paras){
            //http传输必须符合ISO8859-1编码规范，b_iso88591的长度为1，而中文字符b_utf8的长度为3，不指定编码会出现转换错误
            String strChineseUTF8 = new String((para.getValue().getBytes(StandardCharsets.ISO_8859_1)), StandardCharsets.UTF_8);
            paraMap.put(para.getName(), strChineseUTF8);
        }
        return paraMap;
    }

    public static Map<String, String> getParaMap(List<IParameter> paras){
        for (IParameter para:paras){
            //http传输必须符合ISO8859-1编码规范，b_iso88591的长度为1，而中文字符b_utf8的长度为3，不指定编码会出现转换错误
            String strChineseUTF8 = new String((para.getValue().getBytes(StandardCharsets.ISO_8859_1)), StandardCharsets.UTF_8);
            paraMap.put(para.getName(), strChineseUTF8);
        }
        return paraMap;
    }

    /**
     * Processes escaped JSON strings in a given Map.
     */
    public static String processEscapedString (String str) {
        boolean hasEscapedChars = str.contains("\\\"");
//		String unescapedString = "";
        if (hasEscapedChars) {
            str= str.replace("\\\"", "\"");

        }
        return str;
    }
}
