#ifndef DPoL_NODE_H
#define DPoL_NODE_H

#include <algorithm>
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/address.h"
#include "ns3/boolean.h"
#include <map>

#include "block.h"
#include "ivrf.h"




namespace ns3 {

class Address;
class Socket;
class Packet;

class DPoLNode : public Application 
{
  public:
    static TypeId GetTypeId (void);

    void SetPeersAddresses (const std::vector<Ipv4Address> &peers);       

    DPoLNode (void);

    virtual ~DPoLNode (void);

    uint32_t        m_id;                               
    Ptr<Socket>     m_socket;                           
    Ptr<Socket>     m_socketClient;                     
    map<Ipv4Address, Ptr<Socket>>      m_peersSockets;            
    map<Address, std::string>          m_bufferedData;            
    map<uint32_t, Ptr<Socket>>            m_nodeInfoMap;
    queue<Tx>                           m_memPool;


    Address         m_local;                            
    vector<Ipv4Address>  m_peersAddresses;     
    
    int prepare_vote;
    
    vector<TREE_NODE> *ivrtree;
    map<uint32_t, TREE_NODE> root_hashes;
    map<uint32_t, std::array<uint8_t, 32>> randomValues;
    
    struct KeyValue {
        int key;
        uint32_t value;

        // 정렬을 위한 연산자 오버로딩
        bool operator<(const KeyValue& other) const {
            return value < other.value;
        }
    };
		        // 키와 앞 4바이트 값을 저장하는 벡터 생성
    vector<KeyValue> keyValues;
    
    
    //string m_receivedPacketsString;
    std::map<uint32_t, std::vector<uint8_t>> m_receivedPackets;

    AES256_CTR_DRBG_struct s, s_prime;    
    

    int             N; 
    std::vector<int>  values;  

                          
    int             is_producer;
    int             producer;
    int             round;

    int producer_vote;
    int commit_num;

    vector<uint8_t> m_pk;
    vector<uint8_t> m_sk; 

    EC_KEY* m_eckey;
    Block tempBlock;
    Blockchain      m_chain;

    struct TX {
        int v;
        int val;
        int prepare_vote;
        int verify_vote;
        int commit_vote;
    };
    TX tx[1000];


    struct Item {
    uint64_t value;
    uint32_t id;
    
    bool operator<(const Item& other) const {
        return value < other.value; 
    }
    };

    std::multiset<Item> min_heap;


    virtual void StartApplication (void);    
    virtual void StopApplication (void); 
    void HandleRead (Ptr<Socket> socket);

    std::string getPacketContent(Ptr<Packet> packet, Address from); 

    void Send (uint8_t data[], uint32_t dataSize);

    void SendBlock(Block block);

    bool CheckIdInHeap(uint32_t id, const std::multiset<Item>& heap);

    void Find_Minimum(Item item);

    void InitPrevote(void);
    void Prevote(void);

    void broadcastMerkleRoot(void);
  
    uint8_t* GenerateRandom(uint64_t& random_value);
    
    uint8_t * generateTX (int num);

    vector<uint8_t> GetBlockHash(Block block);
    vector<Tx> GetPendingTxs(void);

    Tx GenerateGenesisTx(void);

    Tx GenerateTx(void);
    vector<uint8_t> SignTx(vector<uint8_t> txItem, vector<uint8_t> sk);

    bool VerifyTxs(Block block);
    bool VerifyTx(vector<uint8_t> txItem, vector<uint8_t> sign, vector<uint8_t> pk);



    void InitializeChain(void);

    void InitializeKey(void);

    void InitializeMempool(void);
    

};
/*
enum Message
{
    REQUEST,           // 0       客户端请求        <REQUEST, t>    t:交易
    PRE_PREPARE,       // 1       预准备消息        <PRE_PREPARE, v, n, b>   v:视图编号   b:区块内容   n:该预准备消息在视图中的编号
    PREPARE,           // 2       准备消息          <PREPARE, v, n, H(b)>
    COMMIT,            // 3       提交             <COMMIT, v, n>
    PRE_PREPARE_RES,   // 4       预准备消息的响应   <PRE_PREPARE_RES, v, n, S>           S:State
    PREPARE_RES,       // 5       准备消息响应
    COMMIT_RES,        // 6       提交响应
    REPLY,             // 7       对客户端的回复       
    VIEW_CHANGE        // 8       view_change消息
};
*/


enum Message
{
    INIT,
    PREVOTE,
    REQUEST,        
    PREPARE,        
    PRECOMMIT,
    COMMIT,
    PKSHARE,
    INITPREVOTE     
};

enum State
{
    SUCCESS,                   // 0      成功
    FAILED,                    // 1      失败
};

}
#endif
