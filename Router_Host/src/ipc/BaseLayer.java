package ipc;

import java.util.ArrayList;

interface BaseLayer {
    public final int mnUpperLayerCount = 0;
    public final String mpLayerName = null;
    public final BaseLayer mpUnderLayer = null;
    public final ArrayList<BaseLayer> mpaUpperLayer = new ArrayList<>();

    public String getLayerName();

    public BaseLayer getUnderLayer();

    public BaseLayer getUpperLayer(int nindex);

    public void setUnderLayer(BaseLayer pUnderLayer);

    public void setUpperLayer(BaseLayer pUpperLayer);

    public default void setUnderUpperLayer(BaseLayer pUULayer) {
    }

    public void setUpperUnderLayer(BaseLayer pUULayer);

    public default boolean send(byte[] input, int length) {
        return false;
    }

    public default boolean send(String filename) {
        return false;
    }

    public default boolean receive(byte[] input) {
        return false;
    }

    public default boolean receive() {
        return false;
    }
    //default로 선언 되었으면 interface에서 구현 가능하고, overriding이 가능하다
}
