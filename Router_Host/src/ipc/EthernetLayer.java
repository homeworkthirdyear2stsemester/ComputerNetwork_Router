package ipc;

import java.util.ArrayList;
import java.util.Arrays;

public class EthernetLayer implements BaseLayer {

    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<>();
    private EthernetFrame ethernetHeader = new EthernetFrame();

    public EthernetLayer(String pName) {
        this.pLayerName = pName;
    }

    public void setDestNumber(byte[] array) {
        this.ethernetHeader.enetDstAddr.setAddrData(array);
    }//dst 정보 저장

    public void setSrcNumber(byte[] array) {
        this.ethernetHeader.enetSrcAddr.setAddrData(array);
    }//src 정보 저장

    public byte ethernetHeaderGetType(int index) {
        return this.ethernetHeader.enetType[index];
    }

    private class EthernetAddr {
        private byte[] addr = new byte[6];

        public EthernetAddr() {
            for (int indexOfAddr = 0; indexOfAddr < addr.length; ++indexOfAddr) {
                this.addr[indexOfAddr] = (byte) 0x00;
            }
        }

        public byte getAddrData(int index) {
            return this.addr[index];
        }

        public void setAddrData(byte[] data) {
            this.addr = data;
        }
    }

    private class EthernetFrame {
        EthernetAddr enetDstAddr;//dst 정보
        EthernetAddr enetSrcAddr;//src 정보
        byte[] enetType;
        byte[] enetData;

        public EthernetFrame() {
            this.enetDstAddr = new EthernetAddr();
            this.enetSrcAddr = new EthernetAddr();
            this.enetType = new byte[2];
            this.enetType[0] = 0x08;
            this.enetData = null;
        }
    }

    private byte[] etherNetDst() {
        return this.ethernetHeader.enetDstAddr.addr;
    }

    private byte[] etherNetSrc() {
        return this.ethernetHeader.enetSrcAddr.addr;
    }

    @Override
    public String getLayerName() {
        return pLayerName;
    }

    @Override
    public BaseLayer getUnderLayer() {
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
    }

    @Override
    public BaseLayer getUpperLayer(int nindex) {
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void setUnderLayer(BaseLayer pUnderLayer) {
        if (pUnderLayer == null)
            return;
        this.p_UnderLayer = pUnderLayer;
    }

    @Override
    public void setUpperLayer(BaseLayer pUpperLayer) {
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);//layer추가
        // nUpperLayerCount++;
    }

    @Override
    public void setUpperUnderLayer(BaseLayer pUULayer) {
        this.setUpperLayer(pUULayer);
        pUULayer.setUnderLayer(this);
    }

    @Override
    public synchronized boolean send(byte[] input, int length) {
        byte is_checked = input[0];
        byte[] headerAddedArray = new byte[length + 14];
        int index = 0;

        byte[] dstIp = Arrays.copyOfRange(input, 25, 29);
        byte[] dstMac = ARPLayer.getMacAddress(dstIp);//ip에 따른 mac주소 가져오기

        if (is_checked == 0x06 && input[8] == 0x01) {//arp요청
            while (index < 6) {//브로드캐스트
                headerAddedArray[index] = (byte) 0xff;
                index += 1;
            }
            headerAddedArray[13] = this.ethernetHeader.enetType[1]; //  ARP에서 06 변환해서 보내기
        } else if (is_checked == 0x06 && input[8] == 0x02) {//arp 응답
            while (index < 6) {//요청온 주소
                headerAddedArray[index] = dstMac[index];
                index += 1;
            }
            headerAddedArray[13] = (byte) 0x06;
        } else if (is_checked == 0x08) {//ip

            dstIp = Arrays.copyOfRange(input, 17, 21);
            dstMac = ARPLayer.getMacAddress(dstIp);//ip에 따른 mac주소 가져오기

            while (index < 6) {//해당 mac으로 보냄
                headerAddedArray[index] = dstMac[index];
                index += 1;
            }
            headerAddedArray[13] = this.ethernetHeader.enetType[1]; // ARP에서 00으로 변환해서 보내기
        }

        while (index < 12) { // 나의 mac주소
            headerAddedArray[index] = this.ethernetHeader.enetSrcAddr.getAddrData(index - 6);//내 mac주소
            index += 1;
        }
        headerAddedArray[12] = this.ethernetHeader.enetType[0];
        System.arraycopy(input, 0, headerAddedArray, 14, length);

        return this.getUnderLayer().send(headerAddedArray, headerAddedArray.length);
    }

    @Override
    public synchronized boolean receive(byte[] input) {
        if (!this.isMyAddress(input) && (this.isBoardData(input) || this.isMyConnectionData(input))
                && input[12] == 0x08) {//브로드이거나 나한테
            byte[] removedHeaderData = this.removeCappHeaderData(input);
            if (input[13] == 0x00) {//ip
                return this.getUpperLayer(0).receive(removedHeaderData); // IP Layer
            } else if (input[13] == 0x06) {//arp
                return this.getUpperLayer(1).receive(removedHeaderData); // ARP Layer
            }
        }
        return false;
    }

    private byte[] removeCappHeaderData(byte[] input) {//header 제거
        byte[] removeCappHeader = new byte[input.length - 14];
        System.arraycopy(input, 14, removeCappHeader, 0, removeCappHeader.length);

        return removeCappHeader;
    }

    /*
     * @param  myAddressData : mac주소 byte 배열
     * @param  inputFrameData : header를 재거하지 않은 배열
     * @param  inputDataStartIndex : src : 6, dst : 0을 넣으면 된다 -> 코드 재사용 때문에 사용
     * @return : 비교해서 동일 : true, 다름 : false
     */
    private boolean checkTheFrameData(byte[] myAddressData, byte[] inputFrameData, int inputDataStartIndex) {// add prarmeter 사용,
        for (int index = inputDataStartIndex; index < inputDataStartIndex + 6; index++) {
            if (inputFrameData[index] != myAddressData[index - inputDataStartIndex]) {
                return false;
            }
        }
        return true;
    }

    private boolean isBoardData(byte[] inputFrameData) {
        byte[] boardData = new byte[6];
        for (int index = 0; index < 6; index++) {
            boardData[index] = (byte) 0xFF;
        }
        return this.checkTheFrameData(boardData, inputFrameData, 0);
    }// 브로드 케스트인지 check

    private boolean isMyConnectionData(byte[] inputFrameData) {
        byte[] srcAddr = this.ethernetHeader.enetSrcAddr.addr;
        return this.checkTheFrameData(srcAddr, inputFrameData, 0);
    }// 지금 받은 frame이 나랑 연결된 mac주소인지 판별

    private boolean isMyAddress(byte[] inputFrameData) {
        byte[] srcAddr = this.etherNetSrc();
        return this.checkTheFrameData(srcAddr, inputFrameData, 6);
    }// loop back일 경우 true, 다른 곳에서 온 frame : false

    @Override
    public BaseLayer getUnderLayer(int nindex) {
        return null;
    }
}