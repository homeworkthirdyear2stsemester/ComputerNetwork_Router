package ipc;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

//import static ipc.FileSimplestDlg.mLayerMgr;

public class ARPDlg extends JFrame implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<>();
    private BaseLayer fileUnderLayer;
    private JTextField chattingWrite;

    private ArrayList<MacAndName> storageOfMacList = new ArrayList<>();

    private JTextArea IPAddressArea;
    private JPanel contentPane;
    private JButton ARPCacheSendButton;
    private static JTextArea arpCacheTextArea;
    private JButton allDeleteButton;
    private JButton itemDeleteButton;
    private JButton addButton;
    private JTextArea proxyTextArea;
    private JButton deleteButton;
    private JButton gratuitousARPSendButton;
    private JTextArea hwAddressArea;
    private JButton cancelButton;

    // Proxy ARP


    //Base ARP
    public static byte[] myIPAddress;
    public static byte[] myMacAddress;
    public static byte[] targetIPAddress;


    public byte[] getMyIPAddress() {
        return myIPAddress;
    }

    public void setMyIPAddress(byte[] myIPAddress) {
        ARPDlg.myIPAddress = myIPAddress;
    }

    public byte[] getMyMacAddress() {
        return myMacAddress;
    }

    public void setMyMacAddress(byte[] myMacAddress) {
        ARPDlg.myMacAddress = myMacAddress;
    }

    public byte[] getTargetIPAddress() {
        return targetIPAddress;
    }

    public void setTargetIPAddress(byte[] targetIPAddress) {
        ARPDlg.targetIPAddress = targetIPAddress;
    }


    // Gratuitous
    public static byte[] GratuitousAddress;


    private static String MacToString(byte[] mac) {
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

    public static void updateARPTableToGUI() { // 최신화된 화면 보여줌
        //arp_table

        String result = "";
        for (String key : ARPLayer.arpTable.keySet()) {
            if (ARPLayer.arpTable.get(key).length != 1) {
                result += key + "          " + MacToString(ARPLayer.arpTable.get(key)) + "                    " + "Complete\n";
            } else {
                result += key + "          " + "??????????" + "                    " + "Incomplete\n";
            }
        }
        arpCacheTextArea.setText(result);

    }


    public ARPDlg(String pName) {
        this.pLayerName = pName;
    }

    /**
     * Launch the application.
     */

    /**
     * Create the frame.
     */
    public ARPDlg() {
        setTitle("TestARP");

        setBounds(100, 100, 867, 499);
        contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        setContentPane(contentPane);
        contentPane.setLayout(null);

        JPanel ARPCachePanel = new JPanel();
        ARPCachePanel
                .setBorder(new TitledBorder(null, "ARP Cache", TitledBorder.LEADING, TitledBorder.TOP, null, null));
        ARPCachePanel.setToolTipText("");
        ARPCachePanel.setBounds(14, 12, 384, 385);
        contentPane.add(ARPCachePanel);
        ARPCachePanel.setLayout(null);

        arpCacheTextArea = new JTextArea();
        arpCacheTextArea.setEditable(false);
        arpCacheTextArea.setBounds(14, 23, 356, 189);
        ARPCachePanel.add(arpCacheTextArea);

        itemDeleteButton = new JButton("Item Delete");
        itemDeleteButton.addActionListener(new setAddressListener());
        itemDeleteButton.setBounds(24, 221, 135, 33);
        ARPCachePanel.add(itemDeleteButton);

        allDeleteButton = new JButton("All Delete");
        allDeleteButton.addActionListener(new setAddressListener());
        allDeleteButton.setBounds(209, 221, 135, 33);
        ARPCachePanel.add(allDeleteButton);

        JLabel lblNewLabel = new JLabel("IP 주소");
        lblNewLabel.setBounds(14, 316, 62, 18);
        ARPCachePanel.add(lblNewLabel);

        IPAddressArea = new JTextArea();
        IPAddressArea.setBounds(78, 314, 200, 24);
        ARPCachePanel.add(IPAddressArea);

        ARPCacheSendButton = new JButton("Send");
        ARPCacheSendButton.addActionListener(new setAddressListener());
        ARPCacheSendButton.setBounds(293, 312, 77, 27);
        ARPCachePanel.add(ARPCacheSendButton);

        JPanel ProxyARPPanel = new JPanel();
        ProxyARPPanel.setBorder(
                new TitledBorder(null, "Proxy ARP Entry", TitledBorder.LEADING, TitledBorder.TOP, null, null));
        ProxyARPPanel.setBounds(412, 12, 425, 260);
        contentPane.add(ProxyARPPanel);
        ProxyARPPanel.setLayout(null);

        proxyTextArea = new JTextArea();
        proxyTextArea.setEditable(false);
        proxyTextArea.setBounds(14, 28, 397, 162);
        ProxyARPPanel.add(proxyTextArea);

        addButton = new JButton("Add");
        addButton.addActionListener(new setAddressListener());
        addButton.setBounds(48, 202, 135, 33);
        ProxyARPPanel.add(addButton);

        deleteButton = new JButton("Delete");
        deleteButton.addActionListener(new setAddressListener());
        deleteButton.setBounds(236, 202, 135, 33);
        ProxyARPPanel.add(deleteButton);

        JPanel GratuitousARPPanel = new JPanel();
        GratuitousARPPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Gratuitous ARP",
                TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
        GratuitousARPPanel.setBounds(412, 284, 425, 110);
        contentPane.add(GratuitousARPPanel);
        GratuitousARPPanel.setLayout(null);

        JLabel lblHw = new JLabel("H/W 주소");
        lblHw.setBounds(14, 47, 71, 18);
        GratuitousARPPanel.add(lblHw);

        hwAddressArea = new JTextArea();
        hwAddressArea.setBounds(99, 45, 202, 24);
        GratuitousARPPanel.add(hwAddressArea);

        gratuitousARPSendButton = new JButton("Send");
        gratuitousARPSendButton.addActionListener(new setAddressListener());
        gratuitousARPSendButton.setBounds(334, 43, 77, 27);
        GratuitousARPPanel.add(gratuitousARPSendButton);

        JButton QuitButton = new JButton("종료");
        QuitButton.addActionListener(e -> System.exit(0));
        QuitButton.setBounds(293, 409, 105, 27);
        contentPane.add(QuitButton);

        cancelButton = new JButton("취소");
        cancelButton.setBounds(410, 409, 105, 27);
        cancelButton.addActionListener(new setAddressListener());
        contentPane.add(cancelButton);
        setVisible(true);
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
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
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
    public void setUpperUnderLayer(BaseLayer pUULayer) {
        this.setUpperLayer(pUULayer);
        pUULayer.setUnderLayer(this);
    }

    private class MacAndName {
        public byte[] macAddress;
        public String macName;
        public String macAddressStr;
        public int portNumber;

        public MacAndName(byte[] macAddress, String macName, String macAddressStr, int portNumberOfMac) {
            this.macAddress = macAddress;
            this.macName = macName;
            this.macAddressStr = macAddressStr;
            this.portNumber = portNumberOfMac;
        }
    }

    public byte[] getIPByteArray(String[] data) {
        byte[] newData = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            int temp = Integer.parseInt(data[i]);
            newData[i] = (byte) (temp & 0xFF);
        }
        return newData;
    }

    public byte[] getMacByteArray(String macAddress) {
        byte[] hexTobyteArrayMacAdress = new byte[6];
        String changeMacAddress = macAddress.replaceAll(":", "");
        for (int index = 0; index < 12; index += 2) {
            hexTobyteArrayMacAdress[index / 2] = (byte) ((Character.digit(changeMacAddress.charAt(index), 16) << 4)
                    + Character.digit(changeMacAddress.charAt(index + 1), 16));
        }
        return hexTobyteArrayMacAdress;
    }

    public class setAddressListener implements ActionListener {


        @Override
        public void actionPerformed(ActionEvent e) {
            if (e.getSource() == ARPCacheSendButton) { // 수정
                String IPAddress = IPAddressArea.getText();
                byte[] IPAddressByteArray = getIPByteArray(IPAddress.split("\\."));
                setTargetIPAddress(IPAddressByteArray);
                System.out.println(IPAddress);

                if (!IPAddress.equals("") && (!ARPLayer.containMacAddress(IPAddressByteArray))) {
                    String newResultInArpCahceText = IPAddress + "          ??????????          Incomplete\n";
                    arpCacheTextArea.append(newResultInArpCahceText);
                    IPAddressArea.setText("");
                    //mLayerMgr.getLayer("TCP").send(new byte[1], 1); --> 이전 ARP Send
                } else if (ARPLayer.containMacAddress(IPAddressByteArray)
                        && ARPLayer.arpTable.get(ARPLayer.byteArrayToString(IPAddressByteArray)).length != 1) {
                    byte[] macAddress = ARPLayer.getMacAddress(IPAddressByteArray);
                    IPAddress = IPAddress + "          " + MacToString(macAddress) + "                    Complete\n";
                    arpCacheTextArea.append(IPAddress);
                    IPAddressArea.setText("");
                }
            }
            if (e.getSource() == allDeleteButton) { // 수정
                if (arpCacheTextArea.getText().equals("")) {
                    JOptionPane.showMessageDialog(null, "삭제할 ARP가 존재하지 않습니다.");
                    return;
                }
                int result = JOptionPane.showConfirmDialog(null, "모든 Cache를 삭제하시겠습니까?", "Cache Delete",
                        JOptionPane.OK_CANCEL_OPTION);
                if (result == 0) {
                    arpCacheTextArea.setText("");
                    ARPLayer.RemoveAll_Arp();
                }
            }
            if (e.getSource() == itemDeleteButton) { // 수정
                if (arpCacheTextArea.getText().equals("")) {
                    JOptionPane.showMessageDialog(null, "삭제할 ARP가 존재하지 않습니다.");
                    return;
                }
                String indexValue = JOptionPane.showInputDialog(null, "삭제할 Cache의 인덱스를 입력해주세요(Index : 1부터 시작)",
                        "Cache Delete", JOptionPane.OK_CANCEL_OPTION);
                int indexValueInteger = 0;
                if (indexValue != null) {
                    indexValueInteger = Integer.parseInt(indexValue);
                }
                String[] ARPCacheList = arpCacheTextArea.getText().split("\n");
                String IPAddress = ARPCacheList[indexValueInteger - 1].split("          ")[0];
                String result = "";
                for (int i = 0; i < ARPCacheList.length; i++) {
                    if (i != indexValueInteger - 1) {
                        result = result + ARPCacheList[i] + "\n";
                    }
                }
                arpCacheTextArea.setText(result);
                ARPLayer.Remove_Arp(getIPByteArray(IPAddress.split("\\.")));
            }
            if (e.getSource() == deleteButton) { //수정
                if (proxyTextArea.getText().equals("")) {
                    JOptionPane.showMessageDialog(null, "삭제할 Proxy가 존재하지 않습니다.");
                    return;
                }
                String indexValue = JOptionPane.showInputDialog(null, "삭제할 Proxy의 인덱스를 입력해주세요(Index : 1부터 시작)",
                        "Proxy Delete", JOptionPane.OK_CANCEL_OPTION);
                int indexValueInteger = 0;
                if (indexValue != null) {
                    indexValueInteger = Integer.parseInt(indexValue);
                }
                String[] ProxyData = proxyTextArea.getText().split("\n");
                String result = "";
                for (int i = 0; i < ProxyData.length; i++) {
                    if (i != indexValueInteger - 1) {
                        result = result + ProxyData[i] + "\n";
                    } else {
                        String targetName = ProxyData[i].split("       ")[1];
                        //ARPLayer.Remove_Proxy(getMacByteArray(targetName)); --> 수정
                    }
                }
                proxyTextArea.setText(result);
            }
            if (e.getSource() == addButton) {
                new ProxyDlg();
            }
            if (e.getSource() == gratuitousARPSendButton) {
                String HWAddress = hwAddressArea.getText();
                if (HWAddress.equals("")) {
                    JOptionPane.showMessageDialog(null, "정확한 주소를 입력해주세요.");
                } else {
                    GratuitousAddress = getMacByteArray(HWAddress);
                    myMacAddress = GratuitousAddress;
//                    FileSimplestDlg.srcAddress.setText(HWAddress);

                    //mLayerMgr.getLayer("TCP").send(new byte[1], -1); --> 이전 ARP Send
                    hwAddressArea.setText("");
                }
            }
            if (e.getSource() == cancelButton) {
                setVisible(false);
            }
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
            OkButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    String interfaceString = DeviceText.getText();
                    String ipName = IPText.getText();
                    String ethernetName = EthernetText.getText();
                    if (interfaceString.equals("") || ipName.equals("") || ethernetName.equals("")) {
                        JOptionPane.showMessageDialog(null, "올바른 정보를 입력해주세요");
                    } else {
//                        proxyTextArea.append(interfaceString + "       " + ipName + "       " + ethernetName + "\n");
                        byte[] IPArray = getIPByteArray(ipName.split("\\."));
                        byte[] EthernetArray = getMacByteArray(ethernetName);
                        DeviceText.setText("");
                        IPText.setText("");
                        EthernetText.setText("");
                        setVisible(false);
                        //ARPLayer.Add_Proxy(IPArray, EthernetArray);
                    }
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
    
    public static void main(String[] args) {

//        mLayerMgr.AddLayer(new NILayer("NI"));
//        mLayerMgr.AddLayer(new EthernetLayer("Ethernet"));
//        mLayerMgr.AddLayer(new ARPLayer("ARP"));
//        mLayerMgr.AddLayer(new IPLayer("IP"));
//        mLayerMgr.AddLayer(new ARPDlg("ARPGUI"));
        //mLayerMgr.connectLayers(" NI ( *Ethernet ( *IP *File ( +FileGUI ) *ARPGUI  -ARP *ARP ) )"); --> 연결 수정
        ARPDlg arpDlg = new ARPDlg();
        arpDlg.setVisible(true);
        arpDlg.setDefaultCloseOperation(EXIT_ON_CLOSE);
       
    }

	@Override
	public BaseLayer getUnderLayer(int nindex) {
		// TODO Auto-generated method stub
		return null;
	}
}