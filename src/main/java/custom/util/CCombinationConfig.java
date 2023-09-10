package custom.util;

import custom.util.ICombinationConfig;

import javax.swing.*;



public class CCombinationConfig implements ICombinationConfig {
    private CombinationType combinationType;
    private KeyConfiguration keyConfiguration;
    private boolean processEscapedString;
    private String[] optionalParams;
    private SortOrder sortedMethod;
    private int sortedColumn;
    private String secretKey;
    private String paraConnector;
    private String paraPrefixer;
    private String paraSuffixer;

    // 构造函数和getter/setter方法省略

    @Override
    public CombinationType getCombinationType() {
        return combinationType;
    }

    @Override
    public void setCombinationType(CombinationType combinationType) {
        this.combinationType = combinationType;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
         this.secretKey = secretKey;
    }

    public boolean isProcessEscapedString() {
        return processEscapedString;
    }

    public void setProcessEscapedString(boolean processEscapedString) {
        this.processEscapedString = processEscapedString;
    }

    public String[] getOptionalParams() {
        return optionalParams;
    }

    // 可根据需要添加其他配置项
    public void setOptionalParams(String[] optionalParams) {
        this.optionalParams = optionalParams;
    }

    public KeyConfiguration getKeyConfiguration() {
        return keyConfiguration;
    }

    public void setKeyConfiguration(KeyConfiguration keyConfiguration) {
        this.keyConfiguration = keyConfiguration;
    }

    public SortOrder getSortedMethod() {
        return sortedMethod;
    }
    public void setSortedMethod(SortOrder sortedMethod) {
        this.sortedMethod = sortedMethod;
    }

    public int getSortedColumn() {
        return sortedColumn;
    }

    public void setSortedColumn(int sortedColumn) {
        this.sortedColumn = sortedColumn;
    }

    public String getParaConnector() {
        return paraConnector;
    }

    public void setParaConnector(String paraConnector) {
        this.paraConnector = paraConnector;
    }

    public String getParaPrefixer() {
        return paraPrefixer;
    }

    public void setParaPrefixer(String paraPrefixer) {
        this.paraPrefixer = paraPrefixer;
    }

    public String getParaSuffixer() {
        return paraSuffixer;
    }

    public void setParaSuffixer(String paraSuffixer) {
        this.paraSuffixer = paraSuffixer;
    }
}
