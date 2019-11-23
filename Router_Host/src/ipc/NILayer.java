package ipc;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class NILayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<>();

    private int adapterNumber;//네트워크 어뎁터 인덱스
    public Pcap m_AdapterObject;//네트워크 어뎁터 객체
    public PcapIf device;//네트워크 인터페이스 객체
    public static List<PcapIf> adapterList;//네트워크 인터페이스 목록
    static StringBuilder errbuf = new StringBuilder();//에러 버퍼
    private ReceiveThread thread;

    public void setThreadIsRun(boolean isRun) {
        this.thread.setIsRun(isRun);
    }

    public NILayer(String pName) {
        this.pLayerName = pName;
        adapterNumber = 0;
    }

    public static List<PcapIf> getAdapterListInstance() { // Mac 주소를 가져와 준다. -> GUI Layer에서 호출
        synchronized (List.class) { // 변수에 대한 쓰레드 제어
            if (NILayer.adapterList == null) {
                NILayer.adapterList = new ArrayList<>();
            }
            if (NILayer.adapterList.isEmpty()) {
                NILayer.setAdapterList(); // mac주소 리스트를 받아와준다
            }
        }

        return NILayer.adapterList;
    }

    public static void setAdapterList() {
        int r = Pcap.findAllDevs(adapterList, errbuf);
        //현재 컴퓨터에 존재하는 모든 네트워크 어뎁터 목록 가져오기
        if (r == Pcap.NOT_OK || adapterList.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
        }//네트워크 어뎁터가 하나도 존재하지 않을 경우 에러 처리
    }

    public void setAdapterNumber(int iNum) { // combo box에서 가져온 값을 여기 넣는다
        this.adapterNumber = iNum;//어뎁터 번호 초기화
        this.packetStartDriver();//패킷 드라이버 시작 함수
        this.receive();//패킷 수신함수
    }

    private void packetStartDriver() {//패킷 드라이버 시작 함수
        int snaplen = 64 * 1024;//팻킷 캡처 길이
        int flags = Pcap.MODE_PROMISCUOUS;//모든 패킷 캡처
        int timeout = 10 * 1000;//패킷 캡처 시간
        this.m_AdapterObject = Pcap.openLive(NILayer.adapterList.get(this.adapterNumber).getName(),
                snaplen, flags, timeout, NILayer.errbuf);//pcap 작동 시작
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
    public boolean receive() {//쓰레드 객체 생성
        thread = new ReceiveThread(this.m_AdapterObject, this.getUpperLayer(0));
        Thread obj = new Thread(thread);
        obj.start();

        return false;
    }

    public boolean send(byte[] input, int length) {
        ByteBuffer buf = ByteBuffer.wrap(input);
        if (m_AdapterObject.sendPacket(buf) != Pcap.OK) {
            System.err.println(m_AdapterObject.getErr());
            return false;
        }
        return true;
    }
}

class ReceiveThread implements Runnable {
    private byte[] data;
    private Pcap AdapterObject;
    private BaseLayer UpperLayer;
    private boolean isRun = true;

    void setIsRun(boolean isRun) {
        this.isRun = isRun;
    }

    ReceiveThread(Pcap m_AdapterObject, BaseLayer m_UpperLayer) {
        this.AdapterObject = m_AdapterObject;
        this.UpperLayer = m_UpperLayer;
    }//객체 초기화

    @Override
    public void run() {
        while (true) {
            if (!isRun) {
                System.out.println("Thread is terminated");

                return;
            }
            PcapPacketHandler<String> jpacketHandler = (packet, user) -> {
                data = packet.getByteArray(0, packet.size());//패킷의 데이터 바이트배열와 패킷 크기를 알아냄
                UpperLayer.receive(data);//상위 객체의 receive호출
            };
            AdapterObject.loop(10000, jpacketHandler, "");
        }
    }
}