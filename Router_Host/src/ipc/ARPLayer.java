package ipc;

import java.util.*;

public class ARPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
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
        byte is_checked; // arp이면 06 ip이면 08 -> ethernet에서 구별
        byte[] arp_mac_type;
        byte[] arp_ip_type;
        byte arpMacAddrLen;
        byte arpIpAddrLen;
        byte[] arp_opcode;
        ArpAddress arpSrcaddr;
        ArpAddress arpDstaddr;

        public ArpHeader() {
            this.is_checked = 0x00;
            this.arp_mac_type = new byte[2];
            this.arp_ip_type = new byte[2];
            this.arpMacAddrLen = 0x06;
            this.arpIpAddrLen = 0x04;
            this.arp_opcode = new byte[2];
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
        this.arpHeader.arpSrcaddr.ipAddr = ARPDlg.MyIPAddress; // 출발지 IP주소 = 내 IP주소
        byte[] targetip = Arrays.copyOfRange(input, 13, 17);
        byte[] myip = Arrays.copyOfRange(input, 17, 21);
        if (Arrays.equals(targetip, myip)) { // g ARP : mac 주소 변경
            this.arpHeader.arpSrcaddr.macAddr = ARPDlg.GratuitousAddress; // 출발지 맥주소 = 바뀐주소
            this.arpHeader.arpDstaddr.ipAddr = ARPDlg.MyIPAddress; // 도착지 근원지IP주소 = 내 IP주소
            byte[] arp = objToByteSend(arpHeader, (byte) 0x06, (byte) 0x01);

            return getUnderLayer().send(arp, arp.length);
        } else {
            this.arpHeader.arpSrcaddr.macAddr = ARPDlg.MyMacAddress;
            this.arpHeader.arpDstaddr.ipAddr = ARPDlg.TargetIPAddress;

            this.arpHeader.arpDstaddr.macAddr = new byte[6]; // 다시 0 으로 초기화 해서 잔료 데이터를 없애준다

            byte[] headerAddedArray = objToByteSend(arpHeader, (byte) 0x06, (byte) 0x01);// ARP이고 요청인 헤더
            arpTable.put(byteArrayToString(ARPDlg.TargetIPAddress), new byte[1]);
            ARPDlg.updateARPTableToGUI();

            return this.getUnderLayer().send(headerAddedArray, headerAddedArray.length);
            // EthernetLayer의 send호출
        }
    }

    @Override
    public synchronized boolean receive(byte[] input) {
        byte[] opcode = Arrays.copyOfRange(input, 7, 9);
        byte[] src_mac_address = Arrays.copyOfRange(input, 9, 15);
        byte[] src_ip_address = Arrays.copyOfRange(input, 15, 19);
        byte[] dst_ip_address = Arrays.copyOfRange(input, 25, 29);
        // 리시브드

        if (opcode[0] == 0x00 & opcode[1] == 0x01) {// ARP 요청 받음
            this.setTimer(src_ip_address, 180000);
            ArpHeader responseHeader = new ArpHeader();// 보낼 헤드 생성
            if (Arrays.equals(dst_ip_address, ARPDlg.MyIPAddress)) {// 내 ip로 온 경우 내 IP랑 헤더에 적힌 IP비교 -> 아닐경우 Proxy
                responseHeader.arpSrcaddr.macAddr = ARPDlg.MyMacAddress;// 내 mac주소 넣어준다.
                responseHeader.arpSrcaddr.ipAddr = dst_ip_address;
                responseHeader.arpDstaddr.macAddr = src_mac_address;
                responseHeader.arpDstaddr.ipAddr = src_ip_address;
                this.arpCheckAndPut(src_ip_address, src_mac_address);
            } else if (Arrays.equals(src_ip_address, dst_ip_address)) { //GARP
                this.arpCheckAndPut(src_ip_address, src_mac_address);

                return true;
            } else {// 내 ip로 안옴
                if (proxyTable.containsKey(byteArrayToString(dst_ip_address))) {// 연결된 proxy이다
                    responseHeader.arpSrcaddr.macAddr = ARPDlg.MyMacAddress;// 여기다가 내 Mac주소 넣어준다. ***위에서 고쳐야함***
                    responseHeader.arpSrcaddr.ipAddr = dst_ip_address;
                    responseHeader.arpDstaddr.macAddr = src_mac_address;
                    responseHeader.arpDstaddr.ipAddr = src_ip_address;
                    arpCheckAndPut(src_ip_address, src_mac_address);
                    //Proxy update 할 필요없음 -> 자신이 쳐서 올라가기때문이기때문
                    // swap
                } else {// proxy아님
                    this.arpCheckAndPut(src_ip_address, src_mac_address);

                    return false;// proxy아니고 내꺼도 아니니 버린다
                }
            }
            // isChecked - 0x06-ARP , 0x01-Data
            byte[] responseArp = objToByteSend(responseHeader, (byte) 0x06, (byte) 0x02); // ARP reply -> ARP를 받은 후 답장을 위한 부분

            return this.getUnderLayer().send(responseArp, responseArp.length);
        } else if (opcode[0] == 0x00 & opcode[1] == 0x02) {// 내가 보낸 ARP 요청이 돌아옴 (상대방이 주소를 넣어서 보냄)
            this.setTimer(src_ip_address, 1200000);
            arpCheckAndPut(src_ip_address, src_mac_address);

            return true;
        }

        return false;
    }

    private void setTimer(byte[] src_ip_address, long time) {
        Timer timer = new Timer(byteArrayToString(src_ip_address));
        TimerTask task = new TimerTask() {
            @Override
            public void run() {
                arpTable.remove(Thread.currentThread().getName());
                ARPDlg.updateARPTableToGUI();
            }
        };
        timer.schedule(task, time); // 10초로 지정
    }

    public void arpCheckAndPut(byte[] src_ip_address, byte[] src_mac_address) {
        String stringIpAddress = byteArrayToString(src_ip_address);
        if (arpTable.containsKey(stringIpAddress)) {
            byte[] beforeMacAddress = arpTable.get(stringIpAddress);
            if (beforeMacAddress.length != 1) {
                Set<String> arpTableKeySet = arpTable.keySet();
                for (String arpTableKey : arpTableKeySet) {
                    if (Arrays.equals(arpTable.get(arpTableKey), beforeMacAddress)) {
                        arpTable.replace(arpTableKey, src_mac_address);
                    }
                }
            }
            arpTable.replace(byteArrayToString(src_ip_address), src_mac_address);
            ARPDlg.updateARPTableToGUI();
        } else {
            arpTable.put(stringIpAddress, src_mac_address);
            ARPDlg.updateARPTableToGUI();
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
        byte[] buf = new byte[29]; // ARP Frame
        byte[] srcMac = Header.arpSrcaddr.macAddr;
        byte[] srcIp = Header.arpSrcaddr.ipAddr;
        byte[] dstMac = Header.arpDstaddr.macAddr;
        byte[] dstIp = Header.arpDstaddr.ipAddr;

        buf[0] = is_checked;
        buf[1] = 0x00;
        buf[2] = 0x01;// Hard
        buf[3] = 0x08;
        buf[4] = 0x00;// protocol
        buf[5] = Header.arpMacAddrLen;// 1바이트
        buf[6] = Header.arpIpAddrLen;// 2바이트
        buf[7] = 0x00;
        buf[8] = opcode;
        System.arraycopy(srcMac, 0, buf, 9, 6);// 6바이트
        System.arraycopy(srcIp, 0, buf, 15, 4);// 4바이트
        System.arraycopy(dstMac, 0, buf, 19, 6);// 6바이트
        System.arraycopy(dstIp, 0, buf, 25, 4);// 4바이트

        return buf;
    }

    public static void Add_Proxy(byte[] IP, byte[] Mac) {
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

    public static void Remove_Proxy(byte[] removedIp) {
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
        this.p_UnderLayer = pUnderLayer;
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
}