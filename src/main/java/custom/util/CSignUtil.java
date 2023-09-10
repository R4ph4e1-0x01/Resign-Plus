package custom.util;

import java.util.Map;

public class CSignUtil {

    public static String calcSign(CSignConfig signConfig) {
        String sign = "";
        return sign;
    }


    public static String calcTimeStamp(Map updatedParaMap, CSignConfig signConfig) {
        String timeStamp = "";
        if (signConfig.getTimeStampPara() != null && signConfig.getTimeStampPara().isEmpty()){
            timeStamp = updatedParaMap.get(signConfig.getTimeStampPara()).toString();
        }else {
            if (signConfig.getTimestampLong() != CSignConfig.TIMESTAMP_SECOND) {
                timeStamp = Long.toString(System.currentTimeMillis());
            }else {
                timeStamp = Long.toString(System.currentTimeMillis() / 1000);
            }
        }
        return timeStamp;
    }
}
