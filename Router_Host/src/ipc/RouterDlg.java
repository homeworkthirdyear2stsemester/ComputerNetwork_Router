package ipc;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;

import ipc.IPLayer.Router;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

public class RouterDlg extends JFrame {

	private JPanel contentPane;
	private JTable routingTable;
	private JTable arpTable;
	private JTable proxyTable;
	private JButton routingAddBtn;
	private JButton routingDeleteBtn;
	private JButton arpDeleteBtn;
	private JButton proxyAddBtn;
	private JButton proxyDeleteBtn;
	private JComboBox leftComboBox;
	private JComboBox rightComboBox;
	private JTextArea leftIPTextArea;
	private JTextArea leftMacTextArea;
	private JTextArea rightIPTextArea;
	private JTextArea rightMacTextArea;
	private JButton leftConnectorBtn;
	private JButton rightConnectorBtn;
	private List<MacData> adapterList;

	public static LayerManager mLayerMgr = new LayerManager();

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		mLayerMgr.AddLayer(new ARPLayer("ARP"));
		RouterDlg frame = new RouterDlg();
		frame.setVisible(true);
	}

	/**
	 * Create the frame.
	 */
	public RouterDlg() {
		setTitle("Router");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 1323, 578);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		JPanel routingTablePanel = new JPanel();
		routingTablePanel.setBounds(14, 12, 490, 512);
		contentPane.add(routingTablePanel);
		routingTablePanel.setLayout(null);

		JLabel lblNewLabel = new JLabel("Static Routing Table");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setFont(new Font("굴림", Font.BOLD, 20));
		lblNewLabel.setBounds(14, 12, 462, 47);
		routingTablePanel.add(lblNewLabel);

		routingAddBtn = new JButton("Add");
		routingAddBtn.setBounds(35, 470, 185, 30);
		routingAddBtn.addActionListener(new setAddressListener());
		routingTablePanel.add(routingAddBtn);

		routingDeleteBtn = new JButton("Delete");
		routingDeleteBtn.setBounds(269, 470, 185, 30);
		routingDeleteBtn.addActionListener(new setAddressListener());
		routingTablePanel.add(routingDeleteBtn);

		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(0, 71, 490, 369);
		routingTablePanel.add(scrollPane);

		routingTable = new JTable();
		routingTable.setModel(new DefaultTableModel(new Object[][] {},
				new String[] { "Destination", "NetMask", "Gateway", "Flag", "Interface", "Metric" }));
		routingTable.getColumnModel().getColumn(0).setPreferredWidth(100);
		routingTable.getColumnModel().getColumn(1).setPreferredWidth(100);
		routingTable.getColumnModel().getColumn(2).setPreferredWidth(100);
		scrollPane.setViewportView(routingTable);

		JPanel arpTablePanel = new JPanel();
		arpTablePanel.setBounds(518, 12, 447, 276);
		contentPane.add(arpTablePanel);
		arpTablePanel.setLayout(null);

		JLabel lblNewLabel_1 = new JLabel("ARP Cache Table");
		lblNewLabel_1.setFont(new Font("굴림", Font.BOLD, 20));
		lblNewLabel_1.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel_1.setBounds(14, 12, 419, 39);
		arpTablePanel.add(lblNewLabel_1);

		arpDeleteBtn = new JButton("Delete");
		arpDeleteBtn.addActionListener(new setAddressListener());
		arpDeleteBtn.setBounds(128, 234, 185, 30);

		arpTablePanel.add(arpDeleteBtn);

		JScrollPane scrollPane_1 = new JScrollPane();
		scrollPane_1.setBounds(0, 51, 447, 171);
		arpTablePanel.add(scrollPane_1);

		arpTable = new JTable();
		arpTable.setModel(new DefaultTableModel(new Object[][] {},
				new String[] { "IP Address", "Ethernet Address", "Interface", "Flag" }));
		arpTable.getColumnModel().getColumn(0).setPreferredWidth(100);
		arpTable.getColumnModel().getColumn(1).setPreferredWidth(129);
		scrollPane_1.setViewportView(arpTable);

		JPanel proxyTablePanel = new JPanel();
		proxyTablePanel.setBounds(518, 300, 447, 224);
		contentPane.add(proxyTablePanel);
		proxyTablePanel.setLayout(null);

		JLabel lblProxyArpTable = new JLabel("Proxy ARP Table");
		lblProxyArpTable.setHorizontalAlignment(SwingConstants.CENTER);
		lblProxyArpTable.setFont(new Font("굴림", Font.BOLD, 20));
		lblProxyArpTable.setBounds(14, 12, 419, 39);
		proxyTablePanel.add(lblProxyArpTable);

		proxyAddBtn = new JButton("Add");
		proxyAddBtn.setBounds(14, 182, 185, 30);
		proxyAddBtn.addActionListener(new setAddressListener());
		proxyTablePanel.add(proxyAddBtn);

		proxyDeleteBtn = new JButton("Delete");
		proxyDeleteBtn.setBounds(248, 182, 185, 30);
		proxyDeleteBtn.addActionListener(new setAddressListener());
		proxyTablePanel.add(proxyDeleteBtn);

		JScrollPane scrollPane_2 = new JScrollPane();
		scrollPane_2.setBounds(0, 62, 447, 103);
		proxyTablePanel.add(scrollPane_2);

		proxyTable = new JTable();
		proxyTable.setModel(new DefaultTableModel(new Object[][] {},
				new String[] { "IP Address", "Ethernet Address", "Interface" }));
		proxyTable.getColumnModel().getColumn(0).setPreferredWidth(100);
		proxyTable.getColumnModel().getColumn(1).setPreferredWidth(125);
		proxyTable.getColumnModel().getColumn(2).setPreferredWidth(80);
		scrollPane_2.setViewportView(proxyTable);

		JPanel panel = new JPanel();
		panel.setBounds(979, 12, 314, 512);
		contentPane.add(panel);
		panel.setLayout(null);

		JLabel lblNewLabel_2 = new JLabel("LeftConnector");
		lblNewLabel_2.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel_2.setFont(new Font("굴림", Font.BOLD, 20));
		lblNewLabel_2.setBounds(14, 12, 286, 31);
		panel.add(lblNewLabel_2);

		adapterList = NILayer.getMacAddressFromAdapter();
		String[] macNameList = new String[adapterList.size()];
		for (int i = 0; i < macNameList.length; i++) {
			macNameList[i] = adapterList.get(i).macName;
			System.out.println("macName : " + macNameList[i] + "address : "
					+ MacData.byteMacArrayToStringMac(adapterList.get(i).macAddress));
		}

		leftComboBox = new JComboBox(macNameList);
		leftComboBox.setBounds(14, 55, 286, 31);
		leftComboBox.addActionListener(new setAddressListener());
		panel.add(leftComboBox);

		JLabel lblIp_1 = new JLabel("IP :");
		lblIp_1.setFont(new Font("굴림", Font.PLAIN, 17));
		lblIp_1.setHorizontalAlignment(SwingConstants.RIGHT);
		lblIp_1.setBounds(14, 136, 45, 18);
		panel.add(lblIp_1);

		leftIPTextArea = new JTextArea();
		leftIPTextArea.setBounds(60, 136, 240, 18);
		panel.add(leftIPTextArea);

		JLabel lblMac = new JLabel("MAC :");
		lblMac.setHorizontalAlignment(SwingConstants.RIGHT);
		lblMac.setFont(new Font("굴림", Font.PLAIN, 17));
		lblMac.setBounds(14, 166, 45, 18);
		panel.add(lblMac);

		leftMacTextArea = new JTextArea();
		leftMacTextArea.setBounds(60, 166, 240, 18);
		panel.add(leftMacTextArea);

		leftConnectorBtn = new JButton("Setting");
		leftConnectorBtn.setBounds(60, 196, 185, 30);
		leftConnectorBtn.addActionListener(new setAddressListener());
		panel.add(leftConnectorBtn);

		JLabel lblRightconnector = new JLabel("RightConnector");
		lblRightconnector.setHorizontalAlignment(SwingConstants.CENTER);
		lblRightconnector.setFont(new Font("굴림", Font.BOLD, 20));
		lblRightconnector.setBounds(14, 259, 286, 31);
		panel.add(lblRightconnector);

		rightComboBox = new JComboBox(macNameList);
		rightComboBox.setBounds(14, 302, 286, 31);
		rightComboBox.addActionListener(new setAddressListener());
		panel.add(rightComboBox);

		rightIPTextArea = new JTextArea();
		rightIPTextArea.setBounds(60, 383, 240, 18);
		panel.add(rightIPTextArea);

		JLabel label_1 = new JLabel("IP :");
		label_1.setHorizontalAlignment(SwingConstants.RIGHT);
		label_1.setFont(new Font("굴림", Font.PLAIN, 17));
		label_1.setBounds(14, 383, 45, 18);
		panel.add(label_1);

		JLabel label_2 = new JLabel("MAC :");
		label_2.setHorizontalAlignment(SwingConstants.RIGHT);
		label_2.setFont(new Font("굴림", Font.PLAIN, 17));
		label_2.setBounds(14, 413, 45, 18);
		panel.add(label_2);

		rightMacTextArea = new JTextArea();
		rightMacTextArea.setBounds(60, 413, 240, 18);
		panel.add(rightMacTextArea);

		rightConnectorBtn = new JButton("Setting");
		rightConnectorBtn.setBounds(60, 443, 185, 30);
		rightConnectorBtn.addActionListener(new setAddressListener());
		panel.add(rightConnectorBtn);
	}

	public byte[] getIPByteArray(String[] data) {
		byte[] newData = new byte[data.length];
		for (int i = 0; i < data.length; i++) {
			int temp = Integer.parseInt(data[i]);
			newData[i] = (byte) (temp & 0xFF);
		}
		return newData;
	}

	public static String getIPString(byte[] data) {
		int a = (int) data[0] & 0xff;
		int b = (int) data[1] & 0xff;
		int c = (int) data[2] & 0xff;
		int d = (int) data[3] & 0xff;
		return String.valueOf(a) + "." + String.valueOf(b) + "." + String.valueOf(c) + "." + String.valueOf(d);
	}

	public void updateRoutingTable(List<Router> routingTableList) {
		DefaultTableModel model = (DefaultTableModel) routingTable.getModel();
		int rowCount = model.getRowCount();
		for (int i = rowCount - 1; i >= 0; i--) {
			model.removeRow(i);
		}
		Object[][] list = new Object[routingTableList.size()][6];
		for (int i = 0; i < routingTableList.size(); i++) {
			Router routerIndex = routingTableList.get(i);
			list[i][0] = getIPString(routerIndex._dstAddress);
			list[i][1] = getIPString(routerIndex._netMask);
			list[i][2] = getIPString(routerIndex._gateway);
			list[i][3] = String.valueOf(routerIndex._flag == 0 ? "U" : routerIndex._flag == 1 ? "UG" : "H");
			list[i][4] = String.valueOf(routerIndex._interface);
			list[i][5] = String.valueOf(routerIndex._metric);
		}
		model.addRow(list);

	}

	public class setAddressListener implements ActionListener {

		private void makeLayerAndThreadOpenIfChoosePort(int portNumber, byte[] srcIpAddress, byte[] srcMacAddress) {
			// 모든 객체 생성과 layer를 연결해주는 함수
			Map<String, BaseLayer> layerTable = new HashMap<>();
			// Ip layer, Ethernet layer, NI layer 생성해야 하는 여부 판별 후 호출
			LayerManager.NUMBER_OF_NI_LAYER++;
			NILayer niLayerObject = new NILayer("NI_" + LayerManager.NUMBER_OF_NI_LAYER);
			mLayerMgr.AddLayer(niLayerObject);
			layerTable.put("NI", niLayerObject);

			// ethernet layer 데이터 추가
			LayerManager.NUMBER_OF_ETHERNET_LAYER++;
			EthernetLayer ethernetLayer = new EthernetLayer("Ethernet_" + LayerManager.NUMBER_OF_ETHERNET_LAYER);
			ethernetLayer.setSrcNumber(srcMacAddress);
			mLayerMgr.AddLayer(ethernetLayer);
			layerTable.put("Ethernet", ethernetLayer);

			LayerManager.NUMBER_OF_IP_LAYER++;
			IPLayer ipLayer = new IPLayer("IP_" + LayerManager.NUMBER_OF_IP_LAYER);
			ipLayer.SetIpSrcAddress(srcIpAddress);
			// ipLayer ip주소 넣기
			mLayerMgr.AddLayer(ipLayer);
			layerTable.put("IP", ipLayer);

			this.connectAllLayers(layerTable); // Layer connect

			niLayerObject.setAdapterNumber(portNumber); // create Thread
		}

		/**
		 * @param layerTable : key - layer name, value - layer object
		 */
		private void connectAllLayers(Map<String, BaseLayer> layerTable) {
			BaseLayer ni = layerTable.get("NI");
			BaseLayer ethernet = layerTable.get("Ethernet");
			BaseLayer arp = mLayerMgr.getLayer("ARP");
			BaseLayer ip = layerTable.get("IP");

			ni.setUpperUnderLayer(ethernet); // connect ethernet and ni
			ethernet.setUpperUnderLayer(arp);
			arp.setUpperUnderLayer(ip);
			ethernet.setUpperLayer(ip);
		}

		private void deleteTableRow(JTable target) {
			String indexValue = JOptionPane.showInputDialog(null, "삭제할 Cache의 인덱스를 입력해주세요(Index : 1부터 시작)",
					"Cache Delete", JOptionPane.OK_CANCEL_OPTION);
			int indexValueInteger = 0;
			if (indexValue != null) {
				indexValueInteger = Integer.parseInt(indexValue);
			}
			DefaultTableModel model = (DefaultTableModel) target.getModel();
			model.removeRow(indexValueInteger - 1);
			((IPLayer) mLayerMgr.getLayer("IP")).removeRoutingTable(indexValueInteger - 1);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			if (e.getSource() == routingAddBtn) {
				new RouterAddDlg();

			} else if (e.getSource() == proxyAddBtn) {
				new ProxyDlg();
			} else if (e.getSource() == routingDeleteBtn) {
				deleteTableRow(routingTable);
			} else if (e.getSource() == arpDeleteBtn) {
				deleteTableRow(arpTable);
			} else if (e.getSource() == proxyDeleteBtn) {
				deleteTableRow(proxyTable);
			} else if (e.getSource() == leftComboBox) {
				int index = leftComboBox.getSelectedIndex();
				leftMacTextArea.setText(MacData.byteMacArrayToStringMac(adapterList.get(index).macAddress));
			} else if (e.getSource() == rightComboBox) {
				int index = rightComboBox.getSelectedIndex();
				rightMacTextArea.setText(MacData.byteMacArrayToStringMac(adapterList.get(index).macAddress));
			} else if (e.getSource() == leftConnectorBtn) {
				if (e.getActionCommand().equals("Setting")) {
					String srcMacString = leftMacTextArea.getText();
					String srcIPString = leftIPTextArea.getText();
					byte[] ipAddress = getIPByteArray(srcIPString.split("."));
					// adapterList.get(0).portNumber
					makeLayerAndThreadOpenIfChoosePort(adapterList.get(leftComboBox.getSelectedIndex()).portNumber,
							ipAddress, MacData.stringMacToByteMacArray(srcMacString));
					leftConnectorBtn.setText("Reset");
					leftMacTextArea.enable(false);
					leftIPTextArea.enable(false);
				} else {
					leftMacTextArea.enable(true);
					leftIPTextArea.enable(true);
					leftConnectorBtn.setText("Setting");
				}
			} else if (e.getSource() == rightConnectorBtn) {
				if (e.getActionCommand().equals("Setting")) {
					String srcMacString = rightMacTextArea.getText();
					String srcIPString = rightIPTextArea.getText();
					byte[] ipAddress = getIPByteArray(srcIPString.split("."));
					makeLayerAndThreadOpenIfChoosePort(adapterList.get(rightComboBox.getSelectedIndex()).portNumber,
							ipAddress, MacData.stringMacToByteMacArray(srcMacString));
					rightConnectorBtn.setText("Reset");
					rightMacTextArea.enable(false);
					rightIPTextArea.enable(false);
				} else {
					rightMacTextArea.enable(true);
					rightIPTextArea.enable(true);
					rightConnectorBtn.setText("Setting");
				}
			}
		}

	}

	public class RouterAddDlg extends JFrame {

		private JPanel contentPane;

		/**
		 * Create the frame.
		 */
		public RouterAddDlg() {
			setTitle("Add Router");
			setBounds(100, 100, 482, 373);
			contentPane = new JPanel();
			contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
			setContentPane(contentPane);
			contentPane.setLayout(null);

			JPanel panel = new JPanel();
			panel.setBounds(14, 12, 447, 265);
			contentPane.add(panel);
			panel.setLayout(null);

			JLabel lblNewLabel = new JLabel("Destination");
			lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
			lblNewLabel.setFont(new Font("굴림", Font.BOLD, 18));
			lblNewLabel.setBounds(0, 17, 140, 29);
			panel.add(lblNewLabel);

			JLabel lblNetmask = new JLabel("NetMask");
			lblNetmask.setHorizontalAlignment(SwingConstants.CENTER);
			lblNetmask.setFont(new Font("굴림", Font.BOLD, 18));
			lblNetmask.setBounds(0, 58, 140, 29);
			panel.add(lblNetmask);

			JLabel lblGateway = new JLabel("Gateway");
			lblGateway.setHorizontalAlignment(SwingConstants.CENTER);
			lblGateway.setFont(new Font("굴림", Font.BOLD, 18));
			lblGateway.setBounds(0, 99, 140, 29);
			panel.add(lblGateway);

			JLabel lblFlag = new JLabel("Flag");
			lblFlag.setHorizontalAlignment(SwingConstants.CENTER);
			lblFlag.setFont(new Font("굴림", Font.BOLD, 18));
			lblFlag.setBounds(0, 145, 140, 29);
			panel.add(lblFlag);

			JLabel lblInterface = new JLabel("Interface");
			lblInterface.setHorizontalAlignment(SwingConstants.CENTER);
			lblInterface.setFont(new Font("굴림", Font.BOLD, 18));
			lblInterface.setBounds(0, 186, 140, 29);
			panel.add(lblInterface);

			JTextArea destinationText = new JTextArea();
			destinationText.setBounds(142, 17, 291, 29);
			panel.add(destinationText);

			JTextArea netMaskText = new JTextArea();
			netMaskText.setBounds(142, 58, 291, 29);
			panel.add(netMaskText);

			JTextArea gatewayText = new JTextArea();
			gatewayText.setBounds(142, 99, 291, 29);
			panel.add(gatewayText);

			JTextArea interfaceText = new JTextArea();
			interfaceText.setBounds(142, 186, 291, 29);
			panel.add(interfaceText);

			JCheckBox upCheckBox = new JCheckBox("Up");
			upCheckBox.setBounds(142, 148, 54, 27);
			panel.add(upCheckBox);

			JCheckBox gatewayCheckBox = new JCheckBox("Gateway");
			gatewayCheckBox.setBounds(223, 148, 97, 27);
			panel.add(gatewayCheckBox);

			JCheckBox hostCheckBox = new JCheckBox("Host");
			hostCheckBox.setBounds(336, 148, 97, 27);
			panel.add(hostCheckBox);

			JLabel lblMetric = new JLabel("Metric");
			lblMetric.setHorizontalAlignment(SwingConstants.CENTER);
			lblMetric.setFont(new Font("굴림", Font.BOLD, 18));
			lblMetric.setBounds(0, 224, 140, 29);
			panel.add(lblMetric);

			JTextArea MetrictextArea = new JTextArea();
			MetrictextArea.setBounds(142, 224, 291, 29);
			panel.add(MetrictextArea);

			JButton addBtn = new JButton("추가");
			addBtn.addActionListener(event -> {
				String destination = destinationText.getText();
				String netmask = netMaskText.getText();
				String gateway = gatewayText.getText();
				if (gateway.equals("")) {
					gateway = "*";
				}
				String flag = null;
				if (upCheckBox.isSelected()) {
					flag = "U";
				}
				if (gatewayCheckBox.isSelected()) {
					flag += "G";
				}
				if (hostCheckBox.isSelected()) {
					flag += "H";
				}
				String interfaceString = interfaceText.getText();
				String Metric = MetrictextArea.getText();
				int flagNum = flag.equals("U") ? 0 : flag.equals("UG") ? 1 : 2;
				((IPLayer) mLayerMgr.getLayer("IP")).addRoutingTable(getIPByteArray(destination.split(".")),
						getIPByteArray(netmask.split(".")), getIPByteArray(gateway.split(".")), flagNum,
						Integer.parseInt(interfaceString), Integer.parseInt(Metric));
				DefaultTableModel model = (DefaultTableModel) routingTable.getModel();
				model.addRow(new Object[] { destination, netmask, gateway, flag, interfaceString, Metric });
				destinationText.setText("");
				netMaskText.setText("");
				gatewayText.setText("");
				upCheckBox.setSelected(false);
				gatewayCheckBox.setSelected(false);
				hostCheckBox.setSelected(false);
				interfaceText.setText("");
				MetrictextArea.setText("");
				setVisible(false);

			});
			addBtn.setBounds(81, 289, 105, 27);
			contentPane.add(addBtn);

			JButton cancelBtn = new JButton("취소");
			cancelBtn.setBounds(300, 289, 105, 27);
			contentPane.add(cancelBtn);
			setVisible(true);
		}
	}

	public class ProxyDlg extends JFrame {
		ProxyDlg() {
			setTitle("Proxy ARP Entry 추가");
			setBounds(100, 100, 450, 300);
			contentPane = new JPanel();
			contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
			setContentPane(contentPane);
			contentPane.setLayout(null);

			JLabel lblNewLabel = new JLabel("Interface");
			lblNewLabel.setHorizontalAlignment(SwingConstants.RIGHT);
			lblNewLabel.setBounds(28, 44, 86, 18);
			contentPane.add(lblNewLabel);

			JLabel lblIp = new JLabel("IP 주소");
			lblIp.setHorizontalAlignment(SwingConstants.RIGHT);
			lblIp.setBounds(28, 100, 86, 18);
			contentPane.add(lblIp);

			JLabel lblEthernet = new JLabel("   Ethernet 주소");
			lblEthernet.setBounds(28, 154, 86, 18);
			contentPane.add(lblEthernet);

			JTextArea DeviceText = new JTextArea();
			DeviceText.setBounds(128, 42, 255, 24);
			contentPane.add(DeviceText);

			JTextArea IPText = new JTextArea();
			IPText.setBounds(128, 98, 255, 24);
			contentPane.add(IPText);

			JTextArea EthernetText = new JTextArea();
			EthernetText.setBounds(128, 152, 255, 24);
			contentPane.add(EthernetText);

			JButton OkButton = new JButton("OK");
			OkButton.addActionListener(event -> {
				String interfaceString = DeviceText.getText();
				String ipName = IPText.getText();
				String ethernetName = EthernetText.getText();
				if (interfaceString.equals("") || ipName.equals("") || ethernetName.equals("")) {
					JOptionPane.showMessageDialog(null, "올바른 정보를 입력해주세요");
				} else {
//                        proxyTextArea.append(interfaceString + "       " + ipName + "       " + ethernetName + "\n");
					// byte[] IPArray = getIPByteArray(ipName.split("\\."));
					// byte[] EthernetArray = getMacByteArray(ethernetName);
					DefaultTableModel model = (DefaultTableModel) proxyTable.getModel();
					model.addRow(new Object[] { ipName, ethernetName, interfaceString });
					DeviceText.setText("");
					IPText.setText("");
					EthernetText.setText("");
					setVisible(false);
					// ARPLayer.Add_Proxy(IPArray, EthernetArray);
				}
			});
			OkButton.setBounds(63, 219, 105, 27);
			contentPane.add(OkButton);

			JButton CancelButton = new JButton("Cancel");
			CancelButton.addActionListener(e -> {
				DeviceText.setText("");
				IPText.setText("");
				EthernetText.setText("");
				setVisible(false);
			});

			CancelButton.setBounds(252, 219, 105, 27);
			contentPane.add(CancelButton);

			setVisible(true);
		}
	}
}
