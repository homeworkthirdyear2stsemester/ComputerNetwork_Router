package ipc;

import org.jnetpcap.PcapIf;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

public class FileSimplestDlg extends JFrame implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<>();
    private BaseLayer fileUnderLayer;
    private JButton CacheTableButton;

    public static LayerManager m_LayerMgr = new LayerManager();

    private JTextField ChattingWrite;

    private ArrayList<MacAndName> storageOfMacList = new ArrayList<>();

    public static ARPDlg arpDlg;

    public void setFileUnderLayer(BaseLayer newUnserLayer) {
        this.fileUnderLayer = newUnserLayer;
    }

    public BaseLayer fileUnderLayer() {
        return this.fileUnderLayer;
    }

    Container contentPane;//프레임에 연결된 컨텐트팬을 알아냄

    JTextArea ChattingArea;//화면 보여주는 위치
    public static JTextArea srcAddress;
    public static JTextArea dstIPAddress;
    JTextArea fileUrl;
    JTextArea srcIPAddress;

    JLabel lblsrc;//label 설정 -> 제목 같은거 설정
    JLabel lbldst;
    JLabel lblNICLabel;


    JButton Setting_Button;//port 번호를 입력 받은 후 입력 완료 버튼 설정
    JButton Chat_send_Button;//체팅 완료 후 입력 된 data를 완료 됬다고 확인 하는 버튼
    JButton choiceFileButton;
    JButton sendFileButton;

    JComboBox<String> NICComboBox;
    int adapterNumber = 0;

    JProgressBar progressBar;

    File file;

    String Text;

    public FileSimplestDlg(String pName) {
        pLayerName = pName;

        setTitle("Chat_File_Transfer");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);//Jpanel 에있는 거
        setBounds(250, 250, 644, 470);//Jpanel 에 존재
        contentPane = new JPanel();//객체 생성
        ((JComponent) contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));//마진 넣는거->다운 케스팅
        setContentPane(contentPane);//content pane으로지정
        contentPane.setLayout(null);

        JPanel chattingPanel = new JPanel();// chatting panel
        chattingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "chatting",
                TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
        chattingPanel.setBounds(10, 5, 360, 276);
        contentPane.add(chattingPanel);
        chattingPanel.setLayout(null);

        JPanel chattingEditorPanel = new JPanel();// chatting write panel
        chattingEditorPanel.setBounds(10, 15, 340, 210);
        chattingPanel.add(chattingEditorPanel);
        chattingEditorPanel.setLayout(null);

        ChattingArea = new JTextArea();//입력 받는 위치
        ChattingArea.setEditable(false);
        ChattingArea.setBounds(0, 0, 340, 210);
        chattingEditorPanel.add(ChattingArea);// chatting edit

        JPanel chattingInputPanel = new JPanel();// chatting write panel
        chattingInputPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
        chattingInputPanel.setBounds(10, 230, 250, 20);
        chattingPanel.add(chattingInputPanel);
        chattingInputPanel.setLayout(null);

        ChattingWrite = new JTextField();//객체 생성 - > 입력 받는 부분
        ChattingWrite.setBounds(2, 2, 250, 20);// 249
        chattingInputPanel.add(ChattingWrite);
        ChattingWrite.setColumns(10);// writing area

        JPanel settingPanel = new JPanel();//setting을 위한 위치 지정
        settingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "setting",
                TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
        settingPanel.setBounds(380, 5, 236, 371);
        contentPane.add(settingPanel);
        settingPanel.setLayout(null);

        JPanel sourceAddressPanel = new JPanel();//source address담는 panel
        sourceAddressPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
        sourceAddressPanel.setBounds(10, 204, 170, 20);
        settingPanel.add(sourceAddressPanel);
        sourceAddressPanel.setLayout(null);

        srcAddress = new JTextArea();
        srcAddress.setBounds(0, 0, 170, 20);
        sourceAddressPanel.add(srcAddress);

        lblsrc = new JLabel("Source Mac Address");
        lblsrc.setBounds(10, 172, 170, 20);//위치와 높이지정
        settingPanel.add(lblsrc);//panel 추가

        JPanel destinationAddressPanel = new JPanel();//입력 받는 위치의 GUI 생성
        destinationAddressPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
        destinationAddressPanel.setBounds(10, 268, 170, 20);
        settingPanel.add(destinationAddressPanel);
        destinationAddressPanel.setLayout(null);

        dstIPAddress = new JTextArea();
        dstIPAddress.setBounds(0, 0, 170, 20);
        destinationAddressPanel.add(dstIPAddress);


        NILayer tempNI = (NILayer) m_LayerMgr.GetLayer("NI");
        if (tempNI != null) {
            for (int indexOfPcapList = 0; indexOfPcapList < tempNI.m_pAdapterList.size(); indexOfPcapList += 1) {
                final PcapIf inputPcapIf = tempNI.m_pAdapterList.get(indexOfPcapList);//NILayer의 List를 가져옴
                byte[] macAdress = null;//객체 지정
                try {
                    macAdress = inputPcapIf.getHardwareAddress();
                } catch (IOException e) {
                    System.out.println("Address error is happen");
                }//에러 표출
                if (macAdress == null) {
                    continue;
                }
                this.storageOfMacList.add(new MacAndName(macAdress, inputPcapIf.getDescription(), this.macByteToString(macAdress), indexOfPcapList));
            }//해당 ArrayList에 Mac주소 포트번호 이름, byte배열, Mac주소 String으로 변환한 값, NILayer의 adapterNumber를 저장해 준다.
        }

        String[] nameOfConnection = new String[this.storageOfMacList.size()];
        for (int index = 0; index < this.storageOfMacList.size(); index++) {
            nameOfConnection[index] = this.storageOfMacList.get(index).macName;
        }

        this.NICComboBox = new JComboBox(nameOfConnection);
        this.NICComboBox.setBounds(10, 45, 170, 20);
        settingPanel.add(this.NICComboBox);
        this.NICComboBox.addActionListener(new setAddressListener());

        lblNICLabel = new JLabel("NIC 선택");
        lblNICLabel.setBounds(10, 24, 170, 20);
        settingPanel.add(lblNICLabel);

        lbldst = new JLabel("Destination IP Address");
        lbldst.setBounds(10, 236, 190, 20);
        settingPanel.add(lbldst);

        Setting_Button = new JButton("Setting");// setting
        Setting_Button.setBounds(80, 300, 100, 20);
        Setting_Button.addActionListener(new setAddressListener());
        settingPanel.add(Setting_Button);// setting

        Chat_send_Button = new JButton("Send");
        Chat_send_Button.setBounds(270, 230, 80, 20);
        Chat_send_Button.addActionListener(new setAddressListener());
        Chat_send_Button.setEnabled(false);
        chattingPanel.add(Chat_send_Button);// chatting send button

        JPanel filePanel = new JPanel();//setting을 위한 위치 지정

        filePanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "File Transfer",
                TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
        filePanel.setBounds(10, 285, 360, 90);
        contentPane.add(filePanel);
        filePanel.setLayout(null);

        JPanel fileEditorPanel = new JPanel();// chatting write panel
        fileEditorPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
        fileEditorPanel.setBounds(10, 20, 250, 20);
        filePanel.add(fileEditorPanel);
        fileEditorPanel.setLayout(null);

        fileUrl = new JTextArea();//입력 받는 위치
        fileUrl.setEditable(false);
        fileUrl.setBounds(2, 2, 250, 20);
        fileEditorPanel.add(fileUrl);// chatting edit

        choiceFileButton = new JButton("File...");
        choiceFileButton.setBounds(270, 20, 80, 20);
        choiceFileButton.addActionListener(new setAddressListener());
        choiceFileButton.setEnabled(false);
        filePanel.add(choiceFileButton);// chatting send button

        this.progressBar = new JProgressBar(0, 100);
        this.progressBar.setBounds(10, 50, 250, 20);
        this.progressBar.setStringPainted(true);
        filePanel.add(this.progressBar);

        CacheTableButton = new JButton("CacheTable");
        CacheTableButton.addActionListener(new setAddressListener());
        CacheTableButton.setBounds(10, 332, 170, 27);
        settingPanel.add(CacheTableButton);

        JLabel lblSourceIpAddress = new JLabel("Source IP Address");
        lblSourceIpAddress.setBounds(10, 99, 170, 20);
        settingPanel.add(lblSourceIpAddress);

        JPanel panel = new JPanel();
        panel.setLayout(null);
        panel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
        panel.setBounds(10, 131, 170, 20);
        settingPanel.add(panel);

        srcIPAddress = new JTextArea();
        srcIPAddress.setBounds(0, 0, 170, 20);
        panel.add(srcIPAddress);

        sendFileButton = new JButton("transfer");
        sendFileButton.setBounds(270, 50, 80, 20);
        sendFileButton.addActionListener(new setAddressListener());
        sendFileButton.setEnabled(false);
        filePanel.add(sendFileButton);

        setVisible(true);
    }

    private String macByteToString(byte[] mac) {
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

    public byte[] getIPByteArray(String[] data) {
        byte[] newData = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            int temp = Integer.parseInt(data[i]);
            newData[i] = (byte) (temp & 0xFF);
        }
        return newData;
    }

    private byte[] strToByte(String macAddress) {
        byte[] hexTobyteArrayMacAdress = new byte[6];
        String changeMacAddress = macAddress.replaceAll(":", "");
        for (int index = 0; index < 12; index += 2) {
            hexTobyteArrayMacAdress[index / 2] = (byte) ((Character.digit(changeMacAddress.charAt(index), 16) << 4)
                    + Character.digit(changeMacAddress.charAt(index + 1), 16));
        }
        return hexTobyteArrayMacAdress;
    }

    class setAddressListener implements ActionListener {

        private int findPortNumber(EthernetLayer tempEthernetLayer, String srcMacNumber) {
            for (int index = 0; index < storageOfMacList.size(); index++) {
                MacAndName tempMacObj = storageOfMacList.get(index);
                if (srcMacNumber.equals(tempMacObj.macAddressStr)) {
                    tempEthernetLayer.setSrcNumber(tempMacObj.macAddress);
                    return tempMacObj.portNumber;
                }
            }
            return 0;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            final JFileChooser fileChooser = new JFileChooser();
            ChatAppLayer tempChatAppLayer = (ChatAppLayer) m_LayerMgr.GetLayer("Chat");
            EthernetLayer tempEthernetLayer = (EthernetLayer) m_LayerMgr.GetLayer("Ethernet");
            NILayer tempNILayer = (NILayer) m_LayerMgr.GetLayer("NI");
            if (e.getSource() == Setting_Button) {
                if (e.getActionCommand().equals("Setting")) {
                    String srcMacNumber = srcAddress.getText();
                    adapterNumber = this.findPortNumber(tempEthernetLayer, srcMacNumber);
                    byte[] srcMacAddressArray = strToByte(srcMacNumber);
                    byte[] srcIPAddressArray = getIPByteArray(srcIPAddress.getText().split("\\."));
                    byte[] dstIPAddressArray = getIPByteArray((dstIPAddress.getText().split("\\.")));//입력된 상대 mac주소 byte 배열로 만들기
                    ARPDlg.TargetIPAddress = dstIPAddressArray;
                    ARPDlg.MyIPAddress = srcIPAddressArray;
                    ARPDlg.MyMacAddress = srcMacAddressArray;
                    tempNILayer.setAdapterNumber(adapterNumber);//Pcap 객체 생성 및 모든 data를 받을 준비르 하는 메소드 -> receive가 내부에 포함됨
                    ((JButton) e.getSource()).setText("Reset");
                    this.enableAll(false);
                    this.enableForSendButtons(true);
                    sendFileButton.setEnabled(false);
                } else {
                    tempNILayer.setThreadIsRun(false);
                    byte[] resetByteArray = new byte[6];
                    tempEthernetLayer.setDestNumber(resetByteArray);
                    tempEthernetLayer.setSrcNumber(resetByteArray);
                    this.enableAll(true);
                    this.enableForSendButtons(false);
                    srcIPAddress.selectAll();
                    srcAddress.selectAll();
                    dstIPAddress.selectAll();
                    srcAddress.replaceSelection("");
                    dstIPAddress.replaceSelection("");
                    srcIPAddress.replaceSelection("");
                    ((JButton) e.getSource()).setText("Setting");
                }
            } else if (e.getSource() == Chat_send_Button) {
                String sendMessage = ChattingWrite.getText();
                if (sendMessage.equals("")) {
                    return;
                }
                byte[] arrayOfByte = sendMessage.getBytes();
                if (tempChatAppLayer.Send(arrayOfByte, arrayOfByte.length)) {
                    ChattingArea.append("[SEND] : " + sendMessage + "\n");
                } else {
                    ChattingArea.append("[Error] : send reject\n");
                }
                ChattingArea.selectAll();
                ChattingArea.setCaretPosition(ChattingArea.getDocument().getLength());
                ChattingWrite.selectAll();
                ChattingWrite.replaceSelection("");
            } else if (e.getSource() == NICComboBox) {
                int index = NICComboBox.getSelectedIndex();
                srcAddress.setText(storageOfMacList.get(index).macAddressStr);
            } else if (e.getSource() == choiceFileButton) {//파일 선택 클릭
                int returnVal = fileChooser.showOpenDialog(null);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    file = fileChooser.getSelectedFile();
                    fileUrl.setText(file.getPath());
                }
                sendFileButton.setEnabled(true);
            } else if (e.getSource() == CacheTableButton) {
                arpDlg.setVisible(true);
            }
        }

        private void enableAll(boolean enable) {
            srcAddress.setEnabled(enable);
            dstIPAddress.setEnabled(enable);
            NICComboBox.setEnabled(enable);
            srcIPAddress.setEnabled(enable);
        }

        private void enableForSendButtons(boolean enable) {
            Chat_send_Button.setEnabled(enable);
            choiceFileButton.setEnabled(enable);
            sendFileButton.setEnabled(enable);
        }
    }


    public boolean Receive(byte[] input) {
        /*
         *    과제 채팅 화면에 채팅 보여주기
         */
        String outputStr = new String(input);
        ChattingArea.append("[RECV] : " + outputStr + "\n");
        ChattingArea.selectAll();
        ChattingArea.setCaretPosition(ChattingArea.getDocument().getLength());
        System.out.println(outputStr);
        return true;
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
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);//top에 넣는다
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
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
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

    public static void main(String[] args) {
        // *********************************************
        // TCP, IP, ARP Layer add required
        // *********************************************

        m_LayerMgr.AddLayer(new NILayer("NI"));
        m_LayerMgr.AddLayer(new EthernetLayer("Ethernet"));
        m_LayerMgr.AddLayer(new ARPLayer("ARP"));
        m_LayerMgr.AddLayer(new IPLayer("IP"));
        m_LayerMgr.AddLayer(new TCPLayer("TCP"));
        m_LayerMgr.AddLayer(new ChatAppLayer("Chat"));
        m_LayerMgr.AddLayer(new FileAppLayer("File"));
        m_LayerMgr.AddLayer(new FileSimplestDlg("FileGUI"));
        m_LayerMgr.AddLayer(new ARPDlg("ARPGUI"));
        m_LayerMgr.ConnectLayers(" NI ( *Ethernet ( *IP ( *TCP ( *Chat ( *FileGUI ) *File ( +FileGUI ) *ARPGUI )  -ARP ) *ARP ) )");
        arpDlg = new ARPDlg();
        arpDlg.setVisible(false);
        ((FileSimplestDlg) m_LayerMgr.GetLayer("FileGUI")).setFileUnderLayer(m_LayerMgr.GetLayer("File"));
    }
}