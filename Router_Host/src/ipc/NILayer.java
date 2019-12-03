package ipc;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacketHandler;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class NILayer implements BaseLayer {
    public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<>();

	private int adapterNumber;// �꽕�듃�썙�겕 �뼱�럞�꽣 �씤�뜳�뒪
	public Pcap m_AdapterObject;// �꽕�듃�썙�겕 �뼱�럞�꽣 媛앹껜
	public PcapIf device;// �꽕�듃�썙�겕 �씤�꽣�럹�씠�뒪 媛앹껜
	public static List<PcapIf> adapterList;// �꽕�듃�썙�겕 �씤�꽣�럹�씠�뒪 紐⑸줉
	public static List<MacData> macAddressData;
	static StringBuilder errbuf = new StringBuilder();// �뿉�윭 踰꾪띁
	private ReceiveThread thread;

	public void setThreadIsRun(boolean isRun) {
		this.thread.setIsRun(isRun);
	}

	public NILayer(String pName) {
		this.pLayerName = pName;
		adapterNumber = 0;
	}

	private static void getAdapterListInstance() { // Mac 二쇱냼瑜� 媛��졇�� 以��떎. -> GUI Layer�뿉�꽌 �샇異�
		if (NILayer.adapterList == null) {
			NILayer.adapterList = new ArrayList<>();
		}
		if (NILayer.adapterList.isEmpty()) {
			NILayer.setAdapterList(); // mac二쇱냼 由ъ뒪�듃瑜� 諛쏆븘��以��떎
		}
	}

	public static List<MacData> getMacAddressFromAdapter() {
		if (NILayer.macAddressData == null) {
			macAddressData = new ArrayList<>();
			NILayer.getAdapterListInstance();
			for (int indexOfPcapList = 0; indexOfPcapList < NILayer.adapterList.size(); indexOfPcapList += 1) {
				final PcapIf inputPcapIf = NILayer.adapterList.get(indexOfPcapList);// NILayer�쓽 List瑜� 媛��졇�샂
				byte[] macAddress = null;// 媛앹껜 吏��젙
				try {
					macAddress = inputPcapIf.getHardwareAddress();
				} catch (IOException e) {
					System.out.println("Address error is happen");
				} // �뿉�윭 �몴異�
				if (macAddress == null) {
					continue;
				}
				NILayer.macAddressData
						.add(new MacData(macAddress, inputPcapIf.getDescription() + indexOfPcapList, indexOfPcapList));
			}
		}

		return NILayer.macAddressData;
	}

	public static void setAdapterList() {
		int r = Pcap.findAllDevs(adapterList, errbuf);
		// �쁽�옱 而댄벂�꽣�뿉 議댁옱�븯�뒗 紐⑤뱺 �꽕�듃�썙�겕 �뼱�럞�꽣 紐⑸줉 媛��졇�삤湲�
		if (r == Pcap.NOT_OK || adapterList.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
		} // �꽕�듃�썙�겕 �뼱�럞�꽣媛� �븯�굹�룄 議댁옱�븯吏� �븡�쓣 寃쎌슦 �뿉�윭 泥섎━
	}

	public void setAdapterNumber(int iNum) { // combo box�뿉�꽌 媛��졇�삩 媛믪쓣 �뿬湲� �꽔�뒗�떎
		this.adapterNumber = iNum;// �뼱�럞�꽣 踰덊샇 珥덇린�솕
		this.packetStartDriver();// �뙣�궥 �뱶�씪�씠踰� �떆�옉 �븿�닔
		this.receive();// �뙣�궥 �닔�떊�븿�닔
	}

	private void packetStartDriver() {// �뙣�궥 �뱶�씪�씠踰� �떆�옉 �븿�닔
		int snaplen = 64 * 1024;// �뙸�궥 罹≪쿂 湲몄씠
		int flags = Pcap.MODE_PROMISCUOUS;// 紐⑤뱺 �뙣�궥 罹≪쿂
		int timeout = 1000;// �뙣�궥 罹≪쿂 �떆媛�
		this.m_AdapterObject = Pcap.openLive(NILayer.adapterList.get(this.adapterNumber).getName(), snaplen, flags,
				timeout, NILayer.errbuf);// pcap �옉�룞 �떆�옉
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
		// nUpperLayerCount++;
	}

	@Override
	public void setUpperUnderLayer(BaseLayer pUULayer) {
		this.setUpperLayer(pUULayer);
		pUULayer.setUnderLayer(this);
	}

	@Override
	public boolean receive() {// �벐�젅�뱶 媛앹껜 �깮�꽦
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

	@Override
	public BaseLayer getUnderLayer(int nindex) {
		return null;
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
	}// 媛앹껜 珥덇린�솕

	@Override
	public void run() {
		while (true) {
			if (!isRun) {
				System.out.println("Thread is terminated");

				return;
			}
			PcapPacketHandler<String> jpacketHandler = (packet, user) -> {
				data = packet.getByteArray(0, packet.size());// �뙣�궥�쓽 �뜲�씠�꽣 諛붿씠�듃諛곗뿴�� �뙣�궥 �겕湲곕�� �븣�븘�깂
				UpperLayer.receive(data);// �긽�쐞 媛앹껜�쓽 receive�샇異�
				System.out.println(this.UpperLayer.getLayerName() + " Connect");
			};
			AdapterObject.loop(10000, jpacketHandler, "");
		}
	}
}

class MacData {
	public byte[] macAddress;
	public String macName;
	public int portNumber;

	public MacData(byte[] macAddress, String macName, int portNumberOfMac) {
		this.macAddress = macAddress;
		this.macName = macName;
		this.portNumber = portNumberOfMac;
	}

	public static byte[] stringMacToByteMacArray(String macAddress) {
		byte[] hexTobyteArrayMacAdress = new byte[6];
		String changeMacAddress = macAddress.replaceAll(":", "");
		for (int index = 0; index < 12; index += 2) {
			hexTobyteArrayMacAdress[index / 2] = (byte) ((Character.digit(changeMacAddress.charAt(index), 16) << 4)
					+ Character.digit(changeMacAddress.charAt(index + 1), 16));
		}
		return hexTobyteArrayMacAdress;
	}

	public static String byteMacArrayToStringMac(byte[] mac) {
		final StringBuilder sb = new StringBuilder();

		for (byte nowByte : mac) {
			if (sb.length() != 0) {
				sb.append(":");
			}
			if (0 <= nowByte && nowByte < 16) {
				sb.append("0");
			}
			sb.append(Integer.toHexString((nowByte < 0) ? nowByte + 256 : nowByte).toUpperCase());
		}
		return sb.toString();
	}
}
