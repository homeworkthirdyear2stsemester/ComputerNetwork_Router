package ipc;

import java.util.*;

public class IPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public int nUnderLayerCount = 0;
	public String pLayerName = null;
	public ArrayList<BaseLayer> p_aUnderLayer = new ArrayList<BaseLayer>();
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	private IpHeader ip_header = new IpHeader();
	public static List<Router> routingTable = new ArrayList();
	public static boolean ischeck;
	// 1 : ARP, 0 : Ethernet

	public IPLayer(String pName) {
		pLayerName = pName;
	}

	private byte[] RemoveCappHeader(byte[] input, int length) {
		byte[] temp = new byte[length - 20];
		System.arraycopy(input, 20, temp, 0, length - 20);

		return temp;
	}

	private class Router implements Comparable<Router>{
		public byte[] _dstAddress;
		public byte[] _netMask;
		public byte[] _gateway;
		public int _flag;
		public int _interface;
		public int _metric;

		public Router(byte[] dstAddress,byte[] netmask,byte[] gateway, int flag,int interFace,int metric) {
			this._dstAddress=dstAddress;
			this._netMask=netmask;
			this._gateway=gateway;
			this._flag=flag;
			this._interface=interFace;
			this._metric=metric;
		}

		@Override
		public int compareTo(Router o) {
			int this_value = ((((int)this._netMask[0] & 0xff) << 24) | (((int)this._netMask[1] & 0xff) << 16) | (((int)this._netMask[2] & 0xff) << 8) | (((int)this._netMask[3] & 0xff)));
			int o_value = ((((int)o._netMask[0] & 0xff) << 24) | (((int)o._netMask[1] & 0xff) << 16) | (((int)o._netMask[2] & 0xff) << 8) | (((int)o._netMask[3] & 0xff)));
			if(this_value > o_value) return 1;
			else if(this_value == o_value) return 0;
			else return -1;
		}
	}

	public boolean send(byte[] input, int length) {
//		int resultLength = input.length;
//		this.ip_header.ipDstAddr.addr = new byte[4]; // 헤더 주소 초기화
//		this.ip_header.ipSrcAddr.addr = new byte[4];
//		SetIpSrcAddress(((ARPDlg) this.getUpperLayer(0).getUpperLayer(2)).getMyIPAddress());
//
//		if (length == -1) { // 그래티우스일 경우 ARPLayer로 처리
//			SetIpDstAddress(((ARPDlg) this.getUpperLayer(0).getUpperLayer(2)).getMyIPAddress()); // dst도 내 Mac주소로 해서
//																									// 그래티우스라는걸 작업
//		} else {
//			SetIpDstAddress(((ARPDlg) this.getUpperLayer(0).getUpperLayer(2)).getTargetIPAddress());
//		}
//
//		byte[] temp = objToByte20(this.ip_header, input, resultLength); // multiplexing
//
//		if (ARPLayer.containMacAddress(this.ip_header.ipDstAddr.addr)) {// 목적지 IP주소가 캐싱되어있으면 -> table 존재 -> data
//																		// frame이므로 바로 전송
//			return this.getUnderLayer(0).send(temp, resultLength + 20);// 데이터이므로 Ethernet Layer로 전달
//		}

		// 아니면 ARP 요청이므로 ARP Layer로 전달
		
		if (length == -1) { // GARP 요구시
			int resultLength = input.length;
			this.ip_header.ipDstAddr.addr = new byte[4]; // 헤더 주소 초기화
			this.ip_header.ipSrcAddr.addr = new byte[4];
			SetIpSrcAddress(((ARPDlg) this.getUpperLayer(0).getUpperLayer(2)).getMyIPAddress());
	
			SetIpDstAddress(((ARPDlg) this.getUpperLayer(0).getUpperLayer(2)).getMyIPAddress()); // dst도 내 Mac주소로 해서
																									// 그래티우스라는걸 작업
		} 
		return this.getUnderLayer(0).send(input, input.length);
//		return false;
	}

	private byte[] objToByte20(IpHeader ipHeader, byte[] input, int length) { // 헤더 추가부분

		byte[] buf = new byte[length + 20];

		buf[0] = ipHeader.ipVerlen;
		buf[1] = ipHeader.ipTos;
		buf[2] = (byte) (((length + 20) >> 8) & 0xFF);
		buf[3] = (byte) ((length + 20) & 0xFF);

		buf[4] = (byte) ((ipHeader.ipId >> 8) & 0xFF);
		buf[5] = (byte) (ipHeader.ipId & 0xFF);

		buf[6] = (byte) ((ipHeader.ipFragOff >> 8) & 0xFF);
		buf[7] = (byte) (ipHeader.ipFragOff & 0xFF);

		buf[8] = ipHeader.ipTtl;
		buf[9] = ipHeader.ipProto;

		buf[10] = (byte) ((ipHeader.ipCksum >> 8) & 0xFF);
		buf[11] = (byte) (ipHeader.ipCksum & 0xFF);

		System.arraycopy(ipHeader.ipSrcAddr.addr, 0, buf, 12, 4);
		System.arraycopy(ipHeader.ipDstAddr.addr, 0, buf, 16, 4);
		System.arraycopy(input, 0, buf, 20, length);

		return buf;
	}
	
	public void callARP(byte[]input, byte[] gateway,int inter) throws InterruptedException {
		if(ARPLayer.containMacAddress(gateway)) {
			//ARP에 있음
			this.getUpperLayer(0).getUnderLayer(inter).send(input, input.length);
		}else {
			//ARP에 없음
			SetIpDstAddress(gateway);
			//시간아 멈쳐라
			byte[] arp_Ipheader = objToByte20(ip_header, new byte[1], 1);
			ischeck = true;
			while(ischeck) {
				Thread.sleep(50);
			}
			this.getUnderLayer(1).send(arp_Ipheader,arp_Ipheader.length);
		}
	}
	public boolean addRoutingTable(byte[] dstAddress,byte[] netmask,byte[] gateway, int flag,int interFace,int metric) {
		routingTable.add(new Router(dstAddress,netmask,gateway,flag,interFace,metric));
		Collections.sort(routingTable);
		return false;
	}
	public synchronized boolean receive(byte[] input) {
        // IP 타입 체크 ip_verlen : ip version 0x04      ip_header.ip_tos : type of service 0x00
        if (this.ip_header.ipVerlen != input[1] || this.ip_header.ipTos != input[2]) {
            return false;
        } // ip 버전이 4인거만 받았다 -> 4, 6중에 4만 받음


        int packet_tot_len = ((input[3] << 8) & 0xFF00) + input[4] & 0xFF; //수신된 패킷의 전체 길이
        
//        for (int addr_index_count = 0; addr_index_count < 4; addr_index_count++) { // 내 주소가 아닐 경우 무조건 proxy를 보내는 걸 한다.
//            if (ARPDlg.myIPAddress[addr_index_count] != input[17 + addr_index_count]) {  //수신한 데이터의 목적지 IP주소가 나의 IP주소와 일치하는지 확인
//                return this.getUnderLayer(0).send(input, packet_tot_len);  //일치하지 않으면 프록시 기능으로 대신 전달해야 하는 데이터라고 인지하여 Ethernet Layer에 전달
//                //ethernet send에서 상대 맥주소 테이블에서 찾을때 ARP테이블이랑 proxy테이블 둘다 찾아봐야할듯?
//                //프록시 연결이 되고 데이터가 최종 목적지에 도착하면 최종목적지 arp테이블에 주소가 반영되는지?
//            }
//        }// proxy arp

        //일치하면 최종 목적지가 자신이므로 de-multiplex하고 상위 레이어로 올림
//        byte[] removeHeader=RemoveCappHeader(input, packet_tot_len);
        byte[] ipheader = Arrays.copyOfRange(input, 16, 20);
        for(int i=0;i<routingTable.size();i++) {
        	byte[] netmask = routingTable.get(i)._netMask;
        	byte[] resultOfMask = new byte[4];
        	for(int j=0;j<4;j++) {
        		resultOfMask[j]=(byte) (netmask[j]&ipheader[j]);
        	}
        	if(Arrays.equals(resultOfMask, routingTable.get(i)._dstAddress)) {
        		//같으면
        		if(Arrays.equals(routingTable.get(i)._gateway,new byte[]{(byte) 0xff,(byte) 255,(byte)0xff,(byte)255})) {
	        		try {
						this.callARP(input, routingTable.get(i)._gateway, routingTable.get(i)._interface);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
	        		return true;
        		}else {
        			//state connect
        			try {
						this.callARP(input, ipheader, routingTable.get(i)._interface);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
        			return true;
        		}
        	}
        }
        return false;
    }

	@Override
	public String getLayerName() {
		return pLayerName;
	}

	public BaseLayer getUnderLayer(int nindex) {
		if (nindex < 0 || nindex > nUnderLayerCount || nUnderLayerCount < 0)
			return null;
		return p_aUnderLayer.get(nindex);

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
		this.p_aUnderLayer.add(nUnderLayerCount++, pUnderLayer);
	}

	@Override
	public void setUpperLayer(BaseLayer pUpperLayer) {
		if (pUpperLayer == null)
			return;
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
	}

	@Override
	public void setUpperUnderLayer(BaseLayer pUULayer) {
		this.setUpperLayer(pUULayer);
		pUULayer.setUnderLayer(this);
	}

	// src IP주소 세팅
	public void SetIpSrcAddress(byte[] srcAddress) {
		ip_header.ipSrcAddr.addr = srcAddress;
	}

	// dst IP주소 세팅
	public void SetIpDstAddress(byte[] dstAddress) {
		ip_header.ipDstAddr.addr = dstAddress;

	}

	@Override
	public BaseLayer getUnderLayer() {
		return null;
	}

	// Header 자료구조
	private class IpHeader {
		// ARP면 0x06, 일반 데이터면 0x08 index 0
		byte ipVerlen; // ip version (1byte) index 1
		byte ipTos; // type of service (1byte) index 2
		short ipLen; // total packet length (2byte) index 3~4
		short ipId; // datagram Identification(2byte) index 5~6
		short ipFragOff;// fragment offset (2byte) index 7~8
		byte ipTtl; // time to live in gateway hops (1byte) index 9
		byte ipProto; // IP protocol (1byte) index 10 TCP:6 UDP:17
		short ipCksum; // header checksum (2byte) index 11 12
		// 0~11 index

		IpAddr ipSrcAddr;// source IP address (4byte) 13~16 index
		IpAddr ipDstAddr;// destination IP address (4byte) 17~20 index

		// byte ip_data[]; //variable length data (variable)

		private IpHeader() {

			this.ipVerlen = 0x04; // IPV4 이므로 4로 지정
			this.ipTos = 0x00;
			this.ipLen = 0;
			this.ipId = 0;
			this.ipFragOff = 0;
			this.ipTtl = 0x00;
			this.ipProto = 0x06;
			this.ipCksum = 0;
			this.ipSrcAddr = new IpAddr();
			this.ipDstAddr = new IpAddr();

		}

		// 헤더의 IP주소 자료구조
		private class IpAddr {
			private byte[] addr = new byte[4];

			public IpAddr() {
				this.addr[0] = 0x00;
				this.addr[1] = 0x00;
				this.addr[2] = 0x00;
				this.addr[3] = 0x00;
			}
		}
	}
}