package ipc;

import java.util.*;

public class ARPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<>();
    public static Map<String, byte[]> arp_table = new Hashtable<>();
    public _ARP_HEADER arp_Header = new _ARP_HEADER();
    public static Map<String, byte[]> proxy_table = new Hashtable<>();

    private class _ARP_ADDR {
        private byte[] mac_addr = new byte[6];
        private byte[] ip_addr = new byte[4];

        public _ARP_ADDR() {
            for (int indexOfAddr = 0; indexOfAddr < mac_addr.length; ++indexOfAddr) {
                this.mac_addr[indexOfAddr] = (byte) 0x00;
            }
            for (int indexOfAddr = 0; indexOfAddr < ip_addr.length; ++indexOfAddr) {
                this.ip_addr[indexOfAddr] = (byte) 0x00;
            }
        }
    }

    private class _ARP_HEADER {
        byte is_checked; // arp이면 06 ip이면 08 -> ethernet에서 구별
        byte[] arp_mac_type;
        byte[] arp_ip_type;
        byte arp_mac_addr_len;
        byte arp_ip_addr_len;
        byte[] arp_opcode;
        _ARP_ADDR arp_srcaddr;
        _ARP_ADDR arp_dstaddr;

        public _ARP_HEADER() {
            this.is_checked = 0x00;
            this.arp_mac_type = new byte[2];
            this.arp_ip_type = new byte[2];
            this.arp_mac_addr_len = 0x06;
            this.arp_ip_addr_len = 0x04;
            this.arp_opcode = new byte[2];
            this.arp_srcaddr = new _ARP_ADDR();
            this.arp_dstaddr = new _ARP_ADDR();
        }
    }// 내부 클래스

    public static boolean containMacAddress(byte[] input) {
        return arp_table.containsKey(byteArrayToString(input));
    }// 해당 key 값이 Hashtable에 존재하는지 판별

    public static byte[] getMacAddress(byte[] input) {// IP주소로 mac주소 배열을 받아온다
        String ip = byteArrayToString(input);
        if (arp_table.containsKey(ip)) {
            return arp_table.get(ip);
        }
        return proxy_table.get(ip); // arp에 없을경우 proxy table에서 찾아본다
    }

    @Override
    public synchronized boolean Send(byte[] input, int length) {
        // IPLayer가 arp테이블을 봤는데 없어서 일로 옴
        // ARP를 만든다.
        this.arp_Header.arp_srcaddr.ip_addr = ARPDlg.MyIPAddress; // 출발지 IP주소 = 내 IP주소
        byte[] targetip = Arrays.copyOfRange(input, 13, 17);
        byte[] myip = Arrays.copyOfRange(input, 17, 21);
        if (Arrays.equals(targetip, myip)) { // g ARP : mac 주소 변경
            this.arp_Header.arp_srcaddr.mac_addr = ARPDlg.GratuitousAddress; // 출발지 맥주소 = 바뀐주소
            this.arp_Header.arp_dstaddr.ip_addr = ARPDlg.MyIPAddress; // 도착지 근원지IP주소 = 내 IP주소
            byte[] arp = ObjToByte_Send(arp_Header, (byte) 0x06, (byte) 0x01);

            return GetUnderLayer().Send(arp, arp.length);
        } else {
            this.arp_Header.arp_srcaddr.mac_addr = ARPDlg.MyMacAddress;
            this.arp_Header.arp_dstaddr.ip_addr = ARPDlg.TargetIPAddress;

            this.arp_Header.arp_dstaddr.mac_addr = new byte[6]; // 다시 0 으로 초기화 해서 잔료 데이터를 없애준다

            byte[] headerAddedArray = ObjToByte_Send(arp_Header, (byte) 0x06, (byte) 0x01);// ARP이고 요청인 헤더
            arp_table.put(byteArrayToString(ARPDlg.TargetIPAddress), new byte[1]);
            ARPDlg.updateARPTableToGUI();

            return this.GetUnderLayer().Send(headerAddedArray, headerAddedArray.length);
            // EthernetLayer의 send호출
        }
    }

    @Override
    public synchronized boolean Receive(byte[] input) {
        byte[] opcode = Arrays.copyOfRange(input, 7, 9);
        byte[] src_mac_address = Arrays.copyOfRange(input, 9, 15);
        byte[] src_ip_address = Arrays.copyOfRange(input, 15, 19);
        byte[] dst_ip_address = Arrays.copyOfRange(input, 25, 29);
        // 리시브드

        if (opcode[0] == 0x00 & opcode[1] == 0x01) {// ARP 요청 받음
            this.setTimer(src_ip_address, 180000);
            _ARP_HEADER response_header = new _ARP_HEADER();// 보낼 헤드 생성
            if (Arrays.equals(dst_ip_address, ARPDlg.MyIPAddress)) {// 내 ip로 온 경우 내 IP랑 헤더에 적힌 IP비교 -> 아닐경우 Proxy
                response_header.arp_srcaddr.mac_addr = ARPDlg.MyMacAddress;// 내 mac주소 넣어준다.
                response_header.arp_srcaddr.ip_addr = dst_ip_address;
                response_header.arp_dstaddr.mac_addr = src_mac_address;
                response_header.arp_dstaddr.ip_addr = src_ip_address;
                this.arpCheckAndPut(src_ip_address, src_mac_address);
            } else if (Arrays.equals(src_ip_address, dst_ip_address)) { //GARP
                this.arpCheckAndPut(src_ip_address, src_mac_address);

                return true;
            } else {// 내 ip로 안옴
                if (proxy_table.containsKey(byteArrayToString(dst_ip_address))) {// 연결된 proxy이다
                    response_header.arp_srcaddr.mac_addr = ARPDlg.MyMacAddress;// 여기다가 내 Mac주소 넣어준다. ***위에서 고쳐야함***
                    response_header.arp_srcaddr.ip_addr = dst_ip_address;
                    response_header.arp_dstaddr.mac_addr = src_mac_address;
                    response_header.arp_dstaddr.ip_addr = src_ip_address;
                    arpCheckAndPut(src_ip_address, src_mac_address);
                    //Proxy update 할 필요없음 -> 자신이 쳐서 올라가기때문이기때문
                    // swap
                } else {// proxy아님
                    this.arpCheckAndPut(src_ip_address, src_mac_address);

                    return false;// proxy아니고 내꺼도 아니니 버린다
                }
            }
            // isChecked - 0x06-ARP , 0x01-Data
            byte[] response_arp = ObjToByte_Send(response_header, (byte) 0x06, (byte) 0x02); // ARP reply -> ARP를 받은 후 답장을 위한 부분

            return this.GetUnderLayer().Send(response_arp, response_arp.length);
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
                arp_table.remove(Thread.currentThread().getName());
                ARPDlg.updateARPTableToGUI();
            }
        };
        timer.schedule(task, time); // 10초로 지정
    }

    public void arpCheckAndPut(byte[] src_ip_address, byte[] src_mac_address) {
        String stringIpAddress = byteArrayToString(src_ip_address);
        if (arp_table.containsKey(stringIpAddress)) {
            byte[] beforeMacAddress = arp_table.get(stringIpAddress);
            if (beforeMacAddress.length != 1) {
                Set<String> arpTableKeySet = arp_table.keySet();
                for (String arpTableKey : arpTableKeySet) {
                    if (Arrays.equals(arp_table.get(arpTableKey), beforeMacAddress)) {
                        arp_table.replace(arpTableKey, src_mac_address);
                    }
                }
            }
            arp_table.replace(byteArrayToString(src_ip_address), src_mac_address);
            ARPDlg.updateARPTableToGUI();
        } else {
            arp_table.put(stringIpAddress, src_mac_address);
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

    public static byte[] StringToByte(String data) {
        String[] arrayOfString = data.split("\\.");

        byte[] resultAddress = new byte[arrayOfString.length];
        int length = resultAddress.length;

        for (int index = 0; index < length; index++) {
            resultAddress[index] = Byte.parseByte(arrayOfString[index]);
        }

        return resultAddress;
    }

    public byte[] ObjToByte_Send(_ARP_HEADER Header, byte is_checked, byte opcode) {
        byte[] buf = new byte[29]; // ARP Frame
        byte[] src_mac = Header.arp_srcaddr.mac_addr;
        byte[] src_ip = Header.arp_srcaddr.ip_addr;
        byte[] dst_mac = Header.arp_dstaddr.mac_addr;
        byte[] dst_ip = Header.arp_dstaddr.ip_addr;

        buf[0] = is_checked;
        buf[1] = 0x00;
        buf[2] = 0x01;// Hard
        buf[3] = 0x08;
        buf[4] = 0x00;// protocol
        buf[5] = Header.arp_mac_addr_len;// 1바이트
        buf[6] = Header.arp_ip_addr_len;// 2바이트
        buf[7] = 0x00;
        buf[8] = opcode;
        System.arraycopy(src_mac, 0, buf, 9, 6);// 6바이트
        System.arraycopy(src_ip, 0, buf, 15, 4);// 4바이트
        System.arraycopy(dst_mac, 0, buf, 19, 6);// 6바이트
        System.arraycopy(dst_ip, 0, buf, 25, 4);// 4바이트

        return buf;
    }

    public static void Add_Proxy(byte[] IP, byte[] Mac) {
        proxy_table.put(byteArrayToString(IP), Mac);
    }

    public static void Remove_Arp(byte[] removedIp) { // table에서 arp를 제거하고 GUI에 바로 출력한다.
        arp_table.remove(byteArrayToString(removedIp));
        ARPDlg.updateARPTableToGUI();
    }

    public static void RemoveAll_Arp() { // 모든 ARP를 테이블에서 삭제하고 GUI에 알려준다
        arp_table = new Hashtable<>();
        ARPDlg.updateARPTableToGUI();
    }

    public static void Remove_Proxy(byte[] removedIp) {
        proxy_table.remove(byteArrayToString(removedIp));
    }

    public ARPLayer(String name) {
        this.pLayerName = name;
    }

    @Override
    public String GetLayerName() {
        return pLayerName;
    }

    @Override
    public BaseLayer GetUnderLayer() {
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
    }

    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        if (pUnderLayer == null)
            return;
        this.p_UnderLayer = pUnderLayer;
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);// layer異붽�
    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
    }
}