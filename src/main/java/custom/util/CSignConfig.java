package custom.util;

public class CSignConfig {

    static final byte TIMESTAMP_MILLISECOND = 13;
    static final byte TIMESTAMP_SECOND = 10;

    static final String MD5L = "MD5l";
    static final String MD5U = "MD5u";
    static final String SHA1 = "SHA1";
    static final String SHA256 = "SHA256";

    private String timeStampPara;
    private byte timestampLong;
    private String signAlgorithm;

    public String getTimeStampPara() {
        return timeStampPara;
    }

    public void setTimeStampPara(String timeStampPara) {
        this.timeStampPara = timeStampPara;
    }

    public byte getTimestampLong() {
        return timestampLong;
    }

    public void setTimestampLong(byte timestampLong) {
        this.timestampLong = timestampLong;
    }

    public String getSignAlgorithm() {
        return signAlgorithm;
    }

    public void setSignAlgorithm(String signAlgorithm) {
        this.signAlgorithm = signAlgorithm;
    }
}
