package ipc;

import java.util.*;

public class ARPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public List<BaseLayer> underLayers = new ArrayList<>();
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<>();
    public static Map<String, byte[]> arpTable = new Hashtable<>();
    public ArpHeader arpHeader = new ArpHeader();
    public static Map<String, byte[]> proxyTable = new Hashtable<>();

    private class ArpAddress {
        private byte[] macAddr = new byte[6];
        private byte[] ipAddr = new byte[4];

        public ArpAddress() {
            for (int indexOfAddr = 0; indexOfAddr < macAddr.length; ++indexOfAddr) {
                this.macAddr[indexOfAddr] = (byte) 0x00;
            }
            for (int indexOfAddr = 0; indexOfAddr < ipAddr.length; ++indexOfAddr) {
                this.ipAddr[indexOfAddr] = (byte) 0x00;
            }
        }
    }

    private class ArpHeader {
        byte[] arpMacType;
        byte[] arpIpType;
        byte arpMacAddrLen;
        byte arpIpAddrLen;
        byte[] arpOpcode;
        ArpAddress arpSrcaddr;
        ArpAddress arpDstaddr;

        public ArpHeader() {
            this.arpMacType = new byte[2];
            this.arpIpType = new byte[2];
            this.arpMacAddrLen = 0x06;
            this.arpIpAddrLen = 0x04;
            this.arpOpcode = new byte[2];
            this.arpSrcaddr = new ArpAddress();
            this.arpDstaddr = new ArpAddress();
        }
    }// 내부 클래스

    public static boolean containMacAddress(byte[] input) {
        return arpTable.containsKey(byteArrayToString(input));
    }// 해당 key 값이 Hashtable에 존재하는지 판별

    public static byte[] getMacAddress(byte[] input) {// IP주소로 mac주소 배열을 받아온다
        String ip = byteArrayToString(input);
        if (arpTable.containsKey(ip)) {
            return arpTable.get(ip);
        }
        return proxyTable.get(ip); // arp에 없을경우 proxy table에서 찾아본다
    }

    @Override
    public synchronized boolean send(byte[] input, int length) {
        // IPLayer가 arp테이블을 봤는데 없어서 일로 옴
        // ARP를 만든다.
        this.arpHeader.arpSrcaddr.ipAddr = ARPDlg.myIPAddress; // 출발지 IP주소 = 내 IP주소
        byte[] targetip = Arrays.copyOfRange(input, 12, 16);
        byte[] myip = Arrays.copyOfRange(input, 16, 20);
        if (Arrays.equals(targetip, myip)) { // g ARP : mac 주소 변경
            this.arpHeader.arpSrcaddr.macAddr = ARPDlg.GratuitousAddress; // 출발지 맥주소 = 바뀐주소
            this.arpHeader.arpDstaddr.ipAddr = ARPDlg.myIPAddress; // 도착지 근원지IP주소 = 내 IP주소
            byte[] arp = objToByteSend(arpHeader, (byte) 0x06, (byte) 0x01);
            return getUnderLayer().send(arp, arp.length);
        } else {
            this.arpHeader.arpSrcaddr.macAddr = ARPDlg.myMacAddress;
            this.arpHeader.arpDstaddr.ipAddr = ARPDlg.targetIPAddress;

            this.arpHeader.arpDstaddr.macAddr = new byte[6]; // 다시 0 으로 초기화 해서 잔료 데이터를 없애준다

            byte[] headerAddedArray = objToByteSend(arpHeader, (byte) 0x06, (byte) 0x01);// ARP이고 요청인 헤더
            arpTable.put(byteArrayToString(ARPDlg.targetIPAddress), new byte[1]);
            ARPDlg.updateARPTableToGUI();

            return this.getUnderLayer().send(headerAddedArray, headerAddedArray.length);
            // EthernetLayer의 send호출
        }
    }

    @Override
    public synchronized boolean receive(byte[] input) {
        return false;
    }

    public synchronized boolean receive(byte[] input, int indexOfUnderLayer) {
        byte[] opcode = Arrays.copyOfRange(input, 6, 8);
        byte[] srcMacAddress = Arrays.copyOfRange(input, 8, 14);
        byte[] srcIpAddress = Arrays.copyOfRange(input, 14, 18);
        byte[] dstIpAddress = Arrays.copyOfRange(input, 24, 28);
        // 리시브드

        if (opcode[0] == 0x00 & opcode[1] == 0x01) {// ARP 요청 받음
            this.setTimer(srcIpAddress, 180000);
            ArpHeader responseHeader = new ArpHeader();// 보낼 헤드 생성
            EthernetLayer ethernetLayer = ((EthernetLayer) this.getUnderLayer(indexOfUnderLayer));

            if (proxyTable.containsKey(byteArrayToString(dstIpAddress))) {// 연결된 proxy이다
                responseHeader.arpSrcaddr.macAddr = ARPDlg.myMacAddress;// 여기다가 내 Mac주소 넣어준다. ***위에서 고쳐야함***
                responseHeader.arpSrcaddr.ipAddr = dstIpAddress;
                responseHeader.arpDstaddr.macAddr = srcMacAddress;
                responseHeader.arpDstaddr.ipAddr = srcIpAddress;
                arpCheckAndPut(srcIpAddress, srcMacAddress);
                //Proxy update 할 필요없음 -> 자신이 쳐서 올라가기때문이기때문
                // swap
            } else {// arp get data and arp reply
                responseHeader.arpSrcaddr.macAddr = ((EthernetLayer) this.getUnderLayer(indexOfUnderLayer)).etherNetSrc();// 내 mac주소 넣어준다.
                responseHeader.arpSrcaddr.ipAddr = dstIpAddress;
                responseHeader.arpDstaddr.macAddr = srcMacAddress;
                responseHeader.arpDstaddr.ipAddr = srcIpAddress;
                ethernetLayer.setDestNumber(srcMacAddress);
                ethernetLayer.setEndType((byte) 0x06);

                this.arpCheckAndPut(srcIpAddress, srcMacAddress);
            } // arp table update
            // isChecked - 0x06-ARP , 0x01-Data
            byte[] responseArp = objToByteSend(responseHeader, (byte) 0x06, (byte) 0x02); // ARP reply -> ARP를 받은 후 답장을 위한 부분
            // 헤더를 붙임
            return this.getUnderLayer(indexOfUnderLayer).send(responseArp, responseArp.length);
        } else if (opcode[0] == 0x00 & opcode[1] == 0x02) {// 내가 보낸 ARP 요청이 돌아옴 (상대방이 주소를 넣어서 보냄)
            this.setTimer(srcIpAddress, 1200000);
            arpCheckAndPut(srcIpAddress, srcMacAddress);
            IPLayer.ischeck = false;

            return true;
        }

        return false;
    }

    private void setTimer(byte[] srcIpAddress, long time) {
        Timer timer = new Timer(byteArrayToString(srcIpAddress));
        TimerTask task = new TimerTask() {
            @Override
            public void run() {
                arpTable.remove(Thread.currentThread().getName());
                RouterDlg.updateARPTable();
            }
        };
        timer.schedule(task, time); // 10초로 지정
    }

    public void arpCheckAndPut(byte[] srcIpAddress, byte[] srcMacAddress) {
        String stringIpAddress = byteArrayToString(srcIpAddress);
        if (arpTable.containsKey(stringIpAddress)) {
            byte[] beforeMacAddress = arpTable.get(stringIpAddress);
            if (beforeMacAddress.length != 1) {
                Set<String> arpTableKeySet = arpTable.keySet();
                for (String arpTableKey : arpTableKeySet) {
                    if (Arrays.equals(arpTable.get(arpTableKey), beforeMacAddress)) {
                        arpTable.replace(arpTableKey, srcMacAddress);
                    }
                }
            }
            arpTable.replace(byteArrayToString(srcIpAddress), srcMacAddress);
            RouterDlg.updateARPTable();
        } else {
            arpTable.put(stringIpAddress, srcMacAddress);
            RouterDlg.updateARPTable();
        }
    }

    public static String byteArrayToString(byte[] addressByteArray) {
        StringBuilder stringBuilder = new StringBuilder();
        int lengthOfData = addressByteArray.length - 1;
        for (int index = 0; index < lengthOfData; index++) {
            stringBuilder.append(addressByteArray[index]).append(".");
        }

        stringBuilder.append(addressByteArray[lengthOfData]);

        return stringBuilder.toString();
    }

    public byte[] objToByteSend(ArpHeader Header, byte is_checked, byte opcode) {
        byte[] buf = new byte[28]; // ARP Frame
        byte[] srcMac = Header.arpSrcaddr.macAddr;
        byte[] srcIp = Header.arpSrcaddr.ipAddr;
        byte[] dstMac = Header.arpDstaddr.macAddr;
        byte[] dstIp = Header.arpDstaddr.ipAddr;

        buf[0] = 0x00;
        buf[1] = 0x01;// Hard
        buf[2] = 0x08;
        buf[3] = 0x00;// protocol
        buf[4] = Header.arpMacAddrLen;// 1바이트
        buf[5] = Header.arpIpAddrLen;// 2바이트
        buf[6] = 0x00;
        buf[7] = opcode;
        System.arraycopy(srcMac, 0, buf, 8, 6);// 6바이트
        System.arraycopy(srcIp, 0, buf, 14, 4);// 4바이트
        System.arraycopy(dstMac, 0, buf, 18, 6);// 6바이트
        System.arraycopy(dstIp, 0, buf, 24, 4);// 4바이트

        return buf;
    }

    public static void addProxy(byte[] IP, byte[] Mac) {
        proxyTable.put(byteArrayToString(IP), Mac);
    }

    public static void Remove_Arp(byte[] removedIp) { // table에서 arp를 제거하고 GUI에 바로 출력한다.
        arpTable.remove(byteArrayToString(removedIp));
        ARPDlg.updateARPTableToGUI();
    }

    public static void RemoveAll_Arp() { // 모든 ARP를 테이블에서 삭제하고 GUI에 알려준다
        arpTable = new Hashtable<>();
        ARPDlg.updateARPTableToGUI();
    }

    public static void removeProxy(byte[] removedIp) {
        proxyTable.remove(byteArrayToString(removedIp));
    }

    public ARPLayer(String name) {
        this.pLayerName = name;
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
        this.underLayers.add(pUnderLayer);
    }

    @Override
    public void setUpperLayer(BaseLayer pUpperLayer) {
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);// layer異붽�
    }

    @Override
    public void setUpperUnderLayer(BaseLayer pUULayer) {
        this.setUpperLayer(pUULayer);
        pUULayer.setUnderLayer(this);
    }

    @Override
    public BaseLayer getUnderLayer(int nindex) {
        if (0 <= nindex && nindex <= this.underLayers.size()) {
            return this.underLayers.get(nindex);
        }

        return null;
    }
}