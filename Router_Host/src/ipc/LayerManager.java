package ipc;

import java.util.ArrayList;
import java.util.StringTokenizer;

public class LayerManager {//Layer를 모두 관리 해줌

    private class Node {//String으로 data 저장
        private String token;
        private Node next;

        public Node(String input) {
            this.token = input;
            this.next = null;
        }
    }

    Node mpListHead;//head 지정
    Node mpListTail;//tail 지정

    private int mTop;
    private int mLayerCount;

    private ArrayList<BaseLayer> mpStack = new ArrayList<>();//thread를 담는 stack
    private ArrayList<BaseLayer> mpLayers = new ArrayList<>();


    public LayerManager() {//default 생성자
        mLayerCount = 0;//layer가 0개
        mpListHead = null;//head가 없으므로
        mpListTail = null;//tail도 없으므로
        mTop = -1;//top은 없음 -> 0번 째 index 가 존재 할 수 있으므로
    }

    public void AddLayer(BaseLayer pLayer) {//Layer 추가
        mpLayers.add(mLayerCount++, pLayer);//ArrayList에 추가
        //m_nLayerCount++;
    }


    public BaseLayer getLayer(int nindex) {
        return mpLayers.get(nindex);
    }//해당 위치의 layer를 return 받는다

    public BaseLayer getLayer(String pName) {
        for (int i = 0; i < mLayerCount; i++) {
            if (pName.compareTo(mpLayers.get(i).getLayerName()) == 0)
                return mpLayers.get(i);
        }
        return null;
    }//해당 이름을 가지는 Layer를 넣는다

    public void connectLayers(String pcList) {
        makeList(pcList);//string으로 Node list형성
        linkLayer(mpListHead);//만든 list의 head를 넣기
    }

    private void makeList(String pcList) {
        StringTokenizer tokens = new StringTokenizer(pcList, " ");

        for (; tokens.hasMoreElements(); ) {
            Node pNode = AllocNode(tokens.nextToken());
            addNode(pNode);
        }
    }//pcList의 str를 모두 node로 만들고 LinkedList에 추가 해 준다.

    private Node AllocNode(String pcName) {
        Node node = new Node(pcName);
        return node;
    }//노드 생성 메소드

    private void addNode(Node pNode) {//Node추가 -> head와 tail이 지정됨
        if (mpListHead == null) {
            mpListHead = mpListTail = pNode;
        } else {
            mpListTail.next = pNode;
            mpListTail = pNode;
        }
    }

    private void push(BaseLayer pLayer) {//stack에 추가
        mpStack.add(++mTop, pLayer);
        //mp_Stack.add(pLayer);
        //m_nTop++;
    }

    private BaseLayer pop() {//stack에서 제거
        BaseLayer pLayer = mpStack.get(mTop);
        mpStack.remove(mTop);
        mTop--;//해당 top에 위치한 것을 제거 하기위해 top은 index를 가짐

        return pLayer;
    }

    private BaseLayer top() {//layer의 제일 위에 위치를 return
        return mpStack.get(mTop);
    }

    private void linkLayer(Node pNode) {//head로 시작
        BaseLayer pLayer = null;

        while (pNode != null) {//tail까지 가도록 반복
            if (pLayer == null)
                pLayer = getLayer(pNode.token);//pLayer에 pNode의 string값과 동일한 값의 layer를 return 해줌
            else {
                if (pNode.token.equals("("))
                    push(pLayer);//layer 추가
                else if (pNode.token.equals(")"))
                    pop();//layer 제거
                else {
                    char cMode = pNode.token.charAt(0);//0번 쨰 char
                    String pcName = pNode.token.substring(1);//0번째를 재외한 모든 String

                    pLayer = getLayer(pcName);

                    switch (cMode) {
                        case '*':
                            top().setUpperUnderLayer(pLayer);//layer를 top에 넣기, 현재 class layer를 under layer에 넣기
                            break;
                        case '+':
                            top().setUpperLayer(pLayer);//upper layer에 입력
                            break;
                        case '-':
                            top().setUnderLayer(pLayer);//under layer로 지정
                            break;
                    }
                }
            }
            pNode = pNode.next;//next로 이동
        }
    }
}
