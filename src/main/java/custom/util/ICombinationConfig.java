package custom.util;


/**
 * This interface is used to hold details about how HTTP request parameters are spliced.
 */
public interface ICombinationConfig {

    /**
     * Used to indicate the parameters that are spliced
     */
    enum CombinationType {
        ONLY_KEY_VALUE,
        ONLY_VALUE,
        KEY_SYMBOL_VALUE
    }

    /**
     * Used to indicate the key that are spliced
     */
    enum KeyConfiguration {
        APPEND_TO_END,
        SAME_AS_PARA
    }

    CombinationType getCombinationType();

    void setCombinationType(CombinationType combinationType);


}
