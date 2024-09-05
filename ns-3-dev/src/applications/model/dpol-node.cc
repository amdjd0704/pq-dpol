#include "ns3/address.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/udp-socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "stdlib.h"
#include "ns3/ipv4.h"
#include <ctime>
#include <map>

#include <vector>
#include <queue>
#include <cmath>
#include <iostream>
#include <random>

#include <iomanip>

#include "dpol-node.h"

#include "SHA.h"

#include <oqs/oqs.h>

#include <snappy.h>

#include <chrono>


#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>



random_device rd;
mt19937 gen(rd());
uniform_int_distribution<int> dis (1, 99);

int tx_size;                    
int tx_speed ;                
int v;

float timeout;



static char intToChar(int a) {
    return a + '0';
}
static uint8_t charToInt(char a) {
    return a - '0';
}

float 
getRandomDelay() {
  return ((rand() % 3) * 1.0 + 3) / 1000;
}



namespace ns3 {



int node_num = 100;
int producer_num =  33;
int vote_num =  (int)producer_num/3;




static Network network;
using namespace std;
NS_LOG_COMPONENT_DEFINE ("DPoLNode");
NS_OBJECT_ENSURE_REGISTERED (DPoLNode);



void 
SendPacket(Ptr<Socket> socketClient,Ptr<Packet> p) {
    
    uint8_t *buffer = new uint8_t[8];
   
    p->CopyData(buffer, 1);

    socketClient->Send(p);
}




TypeId
DPoLNode::GetTypeId (void)
{
    static TypeId tid = TypeId ("ns3::DPoLNode")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<DPoLNode> ()
    ;

    return tid;
}

DPoLNode::DPoLNode(void) {

}

DPoLNode::~DPoLNode(void) {
    NS_LOG_FUNCTION (this);
}




Tx
DPoLNode::GenerateGenesisTx(void) {
    uint8_t arr[11];
    network.String2Array("43727970746f4372616674", arr);
    vector<uint8_t> genesisTxItem = network.Array2Bytes(arr, 11);
    Tx genesisTx;
    genesisTx.txItem = genesisTxItem;
    genesisTx.sign = SignTx(genesisTx.txItem, m_sk);
    genesisTx.pk = m_pk;
    return genesisTx;
}

void DPoLNode::InitializeKey(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == NULL) {
        throw std::runtime_error("Failed to initialize Falcon signature scheme");
    }

    std::vector<uint8_t> public_key(sig->length_public_key);
    std::vector<uint8_t> secret_key(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, public_key.data(), secret_key.data()) != OQS_SUCCESS) {
        throw std::runtime_error("Failed to generate Falcon key pair");
    }

    m_pk = public_key;
    m_sk = secret_key;

    OQS_SIG_free(sig);
}


void
    DPoLNode::InitializeChain(void) {
        Block genesisBlock;
        Tx genesisTx = GenerateGenesisTx();

        genesisBlock.header.prevHash.assign(network.prevHashSize, '0');
        genesisBlock.body.txs.push_back(genesisTx);

        m_chain.AddBlock(genesisBlock);
    }

void
DPoLNode::InitializeMempool(void) {
    for (int i = 0; i < network.numTxs; i++) {
        Tx tx = GenerateTx();
        m_memPool.push(tx);
    }
}




Tx
DPoLNode::GenerateTx(void) {
    stringstream randomValue;
    Tx tx;
    int txSize = (dis(gen) % network.maxTxItemSize);

    if (txSize % 2 == 1) { txSize += 1; }
    if (txSize == 0) { txSize += 2; }
    for (int i = 0; i < txSize; i++) {
        randomValue << hex << dis(gen) % 16;
        tx.txItem.push_back(randomValue.str()[i]);
    }
    tx.sign = SignTx(tx.txItem, m_sk);
    tx.pk = m_pk;
    
    return tx;
}

vector<uint8_t> DPoLNode::SignTx(vector<uint8_t> txItem, vector<uint8_t> sk) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == NULL) {
        throw std::runtime_error("Failed to initialize Falcon signature scheme");
    }

    uint8_t *signature = new uint8_t[sig->length_signature];
    size_t sig_len;
    
    if (OQS_SIG_sign(sig, signature, &sig_len, txItem.data(), txItem.size(), sk.data()) != OQS_SUCCESS) {
        throw std::runtime_error("Failed to sign transaction with Falcon");
    }

    vector<uint8_t> sigVector(signature, signature + sig_len);
    delete[] signature;
    OQS_SIG_free(sig);

    return sigVector;
}


bool
DPoLNode::VerifyTxs(Block block) {
    for (int i = 0; i < block.body.txs.size(); i++) {
        Tx tx = block.body.txs[i];
        VerifyTx(tx.txItem, tx.sign, tx.pk);
    }
    return true;
}


bool DPoLNode::VerifyTx(vector<uint8_t> txItem, vector<uint8_t> sign, vector<uint8_t> pk) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == NULL) {
        throw std::runtime_error("Failed to initialize Falcon signature scheme");
    }

    int result = OQS_SIG_verify(sig, txItem.data(), txItem.size(), sign.data(), sign.size(), pk.data());

    OQS_SIG_free(sig);

    return result == OQS_SUCCESS;
}



std::pair<std::vector<uint8_t>, size_t> CompressData(const std::vector<uint8_t>& data) {
    std::string compressed;
    if (!snappy::Compress(reinterpret_cast<const char*>(data.data()), data.size(), &compressed)) {
        throw std::runtime_error("Failed to compress data");
    }

    std::vector<uint8_t> compressedData(compressed.begin(), compressed.end());
    return {compressedData, compressedData.size()};
}
std::pair<std::vector<uint8_t>, size_t> DecompressData(const std::vector<uint8_t>& compressedData) {
    std::string compressed(compressedData.begin(), compressedData.end());
    std::string decompressed;
    
    if (!snappy::Uncompress(compressed.data(), compressed.size(), &decompressed)) {
        throw std::runtime_error("Failed to decompress data");
    }

    std::vector<uint8_t> decompressedData(decompressed.begin(), decompressed.end());
    return {decompressedData, decompressedData.size()};
}
void 
DPoLNode::StartApplication ()
{

    v = 1;       
    
    
    tx_size = 1000;      
    tx_speed = 1000;    
    timeout = 0.1;      
                  
    producer_vote =1;
    commit_num = 0;
    
    
    
    if (!m_socket)
    {
        TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
        m_socket = Socket::CreateSocket (GetNode (), tid);
        InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 7071);
        m_socket->Bind (local);          
        m_socket->Listen ();
    }
    m_socket->SetRecvCallback (MakeCallback (&DPoLNode::HandleRead, this));
    m_socket->SetAllowBroadcast (true);

    // Broadcast node id to peers
    for (auto iter = m_peersAddresses.begin(); iter != m_peersAddresses.end(); ++iter) {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Socket> socketClient = Socket::CreateSocket(GetNode(), tid);
        socketClient->Connect(InetSocketAddress(*iter, 7071));
        m_peersSockets[*iter] = socketClient;
        
        uint8_t data[5];
        data[0] = intToChar(INIT);
        data[1] = intToChar((m_id >> 24) & 0xFF);
        data[2] = intToChar((m_id >> 16) & 0xFF);
        data[3] = intToChar((m_id >> 8) & 0xFF);
        data[4] = intToChar(m_id & 0xFF);

        Ptr<Packet> packet = Create<Packet>(data, sizeof(data));
        socketClient->Send(packet);
    }
    
    InitializeKey();
    InitializeChain();
    InitializeMempool();
    
    broadcastMerkleRoot();
    

    
    
    
   
}


void 
DPoLNode::StopApplication ()
{
   delete ivrtree;
   if (m_socket) {
        m_socket->Close();
        m_socket = 0;
    }
}



void
DPoLNode::HandleRead (Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    Address from;
    Address localAddress;

    while ((packet = socket->RecvFrom (from)))
    {

        
        
        if (packet->GetSize () == 0)
        {   
            break;
        }
        
        if (InetSocketAddress::IsMatchingType (from))
        {
            
           uint8_t *b = new uint8_t[8];
            packet->CopyData(b, 8);
            
            switch (charToInt(b[0]))
            {
                
                case INIT:
                {
                    uint32_t id= (static_cast<uint32_t>(charToInt(b[1])) << 24) | 
                    (static_cast<uint32_t>(charToInt(b[2])) << 16) |
                    (static_cast<uint32_t>(charToInt(b[3])) << 8) |
                    static_cast<uint32_t>(charToInt(b[4]));
                    m_nodeInfoMap[id] = socket;
                    break;
                }

    
                case PREPARE:           
                {   

                   uint32_t pktSize = packet->GetSize();
                    std::vector<uint8_t> buffer(pktSize);
                    packet->CopyData(buffer.data(), pktSize);
                     

                    uint32_t totalsequenceNumber = (buffer[6] << 8) | buffer[7];
                    uint32_t sequenceNumber = (buffer[8] << 8) | buffer[9];

                    //printf("\ntest4 %d %d",m_receivedPackets.size(), totalsequenceNumber);
                    m_receivedPackets[sequenceNumber] = std::vector<uint8_t>(buffer.begin() + 10, buffer.end());
                       
                    if ( m_receivedPackets.size()== totalsequenceNumber) {
                        std::vector<uint8_t> m_receivedPacketsVector;
                        for (auto it = m_receivedPackets.begin(); it != m_receivedPackets.end(); /* 빈칸 */) {
                            m_receivedPacketsVector.insert(m_receivedPacketsVector.end(), it->second.begin(), it->second.end());
                            it = m_receivedPackets.erase(it); // 요소를 삭제하고 다음 요소로 이동
                        }
                        auto [decompressedData, decompressedSize] = DecompressData(m_receivedPacketsVector);
                        
                        std::string m_receivedPacketsString(m_receivedPacketsVector.begin(), m_receivedPacketsVector.end());
                            tempBlock.DeserializeBlock(m_receivedPacketsString);

                            if( is_producer==1){
                            
                            uint8_t verify =1;//VerifyTxs(tempBlock);
                            if (verify==1){
                                prepare_vote++;
                            }
                            //검증 후 전송
                            
                            uint8_t *data = (uint8_t *)std::malloc(7);
                            //printf("\n b test %d",charToInt(b[1]));
                            data[0] = intToChar(PRECOMMIT);
                            data[1] = ((b[1]));      // v
                            data[2] = intToChar(verify);
                            data[3] = ((b[2]));
                            data[4] = ((b[3]));
                            data[5] = ((b[4]));
                            data[6] = ((b[5])); 
                            Ptr<Packet> p;
                            Send(data, 7);
                            free(data);
		                }
                    
                    }
                    break;
                }

            case PRECOMMIT:           
                {   
                    int index = charToInt(b[1]);
                    
                    uint8_t verify;
                    if (charToInt(b[2]) == 1) {
                        verify=1;
                        
                    }
                    tx[index].prepare_vote++;
                    if (verify==1){
                    	tx[index].verify_vote++;
                    }
                    
                    if(tx[index].prepare_vote == producer_num-2){
                        
                        if (tx[index].verify_vote >= vote_num) {
                            
                            m_chain.AddBlock(tempBlock);
                            
                            if((index)%(producer_num)== 0){ 
                               
                                is_producer= 0;
                                
                                InitPrevote();
                                break;
                            }
                        //printf("\n%d, %d",keyValues[index%producer_num].key,m_id);
                        if(keyValues[index%producer_num].key == m_id){
                            
                            printf("\nID %d BLOCK %d \n",m_id,index);
                                    double currentTime = Simulator::Now().GetSeconds();
                                    NS_LOG_UNCOND("Current simulation time: " << currentTime << " seconds");
                            
                                    vector<uint8_t> prevHash = GetBlockHash(m_chain.GetLatestBlock());
                                    vector<Tx> txs = GetPendingTxs();
                                    Block newBlock(prevHash, txs);
                                    tempBlock = newBlock;
                                    double delay = getRandomDelay();
                                    Simulator::Schedule(Seconds(delay), &DPoLNode::SendBlock, this, newBlock);
                            
                            }
                        }
                    
                    }
                    
                    
                    break;
                }

                case COMMIT:           
                {   
                
                    
                    break;
                }
                case PKSHARE:           
                { 
                    uint32_t pktSize = packet->GetSize();
                    uint8_t *buffer = new uint8_t[pktSize];
   
                    packet->CopyData(buffer, pktSize);
                
                    uint32_t id = (static_cast<uint32_t>((buffer[1])) << 24) | 
                    (static_cast<uint32_t>((buffer[2])) << 16) |
                    (static_cast<uint32_t>((buffer[3])) << 8) |
                    static_cast<uint32_t>((buffer[4]));
                    
                    memcpy(root_hashes[id].hash, buffer+5, HASH_LENGTH);
                    producer_vote++;
                    if(producer_vote==node_num){
                        
                       producer_vote=1;
	               InitPrevote();
                   }
                     
                    
                    
		    break;
                }
                case INITPREVOTE:           
                { 
                    
		    uint32_t pktSize = packet->GetSize();
                    uint8_t *buffer = new uint8_t[pktSize];
    
                    packet->CopyData(buffer, pktSize);
                    
                    uint32_t i_in=0, j_in=0;
		    unsigned char v[HASH_LENGTH], y[HASH_LENGTH];
		    std::vector<TREE_NODE> ap(LOGN);
		    unsigned char mu1[MU_LENGTH]={0,}, mu2[MU_LENGTH]={0,};
				    
		    unsigned char pk[OQS_SIG_falcon_512_length_public_key], sig[OQS_SIG_falcon_512_length_signature];
		    size_t sig_len;
		    
		     size_t offset = 5;
		    uint32_t uintid = (static_cast<uint32_t>((buffer[1])) << 24) | 
                    (static_cast<uint32_t>((buffer[2])) << 16) |
                    (static_cast<uint32_t>((buffer[3])) << 8) |
                    static_cast<uint32_t>((buffer[4]));
                    
                   
		    unsigned char id[4];
		    id[0] = (uintid >> 24) & 0xFF;
		    id[1] = (uintid >> 16) & 0xFF;
		    id[2] = (uintid >> 8) & 0xFF;
		    id[3] = uintid & 0xFF;
		    
		     SHA256(id, sizeof(id), mu2);
    
		     //vector<uint8_t> prevHash = GetBlockHash(m_chain.GetLatestBlock());
		     //std::memcpy(mu1, prevHash.data(), 32);
                    
                    uint8_t sig_len_bytes[sizeof(size_t)]={0,};
		     
		     
		     memcpy(sig_len_bytes, buffer+offset, sizeof(size_t));
		     offset += sizeof(size_t);
		     
		     memcpy(v, buffer+offset, HASH_LENGTH);
		     offset += HASH_LENGTH;
		  
		    // y 추가
		     memcpy(y, buffer+offset, HASH_LENGTH);
		     offset += HASH_LENGTH;
		    // ap 추가
		     memcpy(ap.data(), buffer+offset, 32 * LOGN);
		     offset += 32 * LOGN;
		    // pk 추가
		     memcpy(pk, buffer+offset,OQS_SIG_falcon_512_length_public_key);
		     offset += OQS_SIG_falcon_512_length_public_key;
 
		     
		    size_t value = 0;
		    for (size_t i = 0; i < sizeof(size_t); ++i) {
		        
			value |= static_cast<size_t>(charToInt(sig_len_bytes[i])) << (i * 8);
		    }
		    
		    sig_len = value;
		    
		     
		    memcpy(sig, buffer+offset, sig_len);
		     
		     
		     
                    int verify_res = verify(mu1, mu2, i_in, j_in, v, y, ap, pk, sig, sig_len, &root_hashes[uintid]);
		
		    if(verify_res==1){
		    
		    
		        std::array<unsigned char, 32> arr;
		        std::copy(std::begin(v), std::end(v), arr.begin());
        
		        randomValues[uintid] = arr;
		        
		    }
		     
		     producer_vote++;
		     if(producer_vote==node_num){
		     producer_vote=1;
		        vector<KeyValue> kv;
		        keyValues =kv;
		        

		        for (const auto &pair : randomValues) {
		                uint32_t current_value = 0;
				for (int i = 0; i < 4; ++i) {
				    current_value = (current_value << 8) | pair.second[i];
				}
				    
		                keyValues.push_back({pair.first, current_value});
		        }
                       
		        std::sort(keyValues.begin(), keyValues.end());
		        
		        
    		        for (int i = 0; i < producer_num; ++i) {
    		            
    		            if(keyValues[i].key==m_id){
    		            	 is_producer= 1;
    		            	//printf(" %d ", is_producer );
    		               if(keyValues[0].key == m_id){
    		               
    		                   printf("\n producer %d",m_id);
                               
    		                   vector<uint8_t> prevHash = GetBlockHash(m_chain.GetLatestBlock());
    		                   vector<Tx> txs = GetPendingTxs();
    		                   Block newBlock(prevHash, txs);
    		                    tempBlock = newBlock;
    		                   Simulator::Schedule(Seconds(timeout), &DPoLNode::SendBlock, this, newBlock);
    		               }
    		            }
    		            
    		        }
		     }
		    break;
                }
                default:
                {
                    
                    NS_LOG_INFO("Wrong msg");
                    
                    break;
                }
            }
        }
        socket->GetSockName (localAddress);
        
    }
}



std::string 
DPoLNode::getPacketContent(Ptr<Packet> packet, Address from) 
{ 
    
    char *packetInfo = new char[packet->GetSize () + 1];
    std::ostringstream totalStream;
    packet->CopyData (reinterpret_cast<uint8_t*>(packetInfo), packet->GetSize ());
    packetInfo[packet->GetSize ()] = '\0'; 
    totalStream << m_bufferedData[from] << packetInfo; 
    std::string totalReceivedData(totalStream.str());

    return totalReceivedData;
}  

void 
DPoLNode::Send (uint8_t data[], uint32_t dataSize)
{   

  Ptr<Packet> p;
  p = Create<Packet> (data, dataSize);
  
  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");

  std::vector<Ipv4Address>::iterator iter = m_peersAddresses.begin();

  while(iter != m_peersAddresses.end()) {
    TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
    
    Ptr<Socket> socketClient = m_peersSockets[*iter];
    double delay = getRandomDelay();
    Simulator::Schedule(Seconds(delay), SendPacket, socketClient, p);
    iter++;
  }
}

void
DPoLNode::SendBlock(Block block) {

    auto serializedBlock = block.SerializeBlock();
    
    auto compressed = CompressData(serializedBlock.first);

    int dataSize = compressed.second;
    const std::vector<uint8_t>& compressedData = compressed.first; 
    int maxPacketSize = 600000;
    
    int numPackets = static_cast<int>(std::ceil(static_cast<double>(compressed.second) / maxPacketSize));
    size_t remainingSize = compressed.second;

    const uint8_t* currentPtr = compressedData.data();

    for (int packetIndex = 0; packetIndex < numPackets; ++packetIndex) {
        int currentPacketSize = (remainingSize >= maxPacketSize) ? maxPacketSize : remainingSize;

        std::vector<uint8_t> packetData;

        std::vector<uint8_t> data(10);

        data[0] = intToChar(PREPARE);
        data[1] = intToChar(v);
        data[2] = intToChar((m_id >> 24) & 0xFF);
        data[3] = intToChar((m_id >> 16) & 0xFF);
        data[4] = intToChar((m_id >> 8) & 0xFF);
        data[5] = intToChar(m_id & 0xFF);
        data[6] = (numPackets>>8) & 0xFF;
        data[7] = (numPackets & 0xFF);
        data[8] = (packetIndex>>8) & 0xFF;
        data[9] = (packetIndex & 0xFF);
        packetData.insert(packetData.end(), std::begin(data), std::end(data));

        packetData.insert(packetData.end(), currentPtr, currentPtr + currentPacketSize);

        Send(packetData.data(), packetData.size());

        currentPtr += currentPacketSize;
        remainingSize -= currentPacketSize;
    }

    v++;
}







bool DPoLNode::CheckIdInHeap(uint32_t id, const std::multiset<Item>& heap){
    for (const auto& it : heap) {
        if (it.id == id) {
            return true;
        }
    }
    return false;
}

void 
DPoLNode::broadcastMerkleRoot(void){
    
    ivrtree = new std::vector<TREE_NODE>(2 * N);
    AES256_CTR_DRBG_struct s_orig, s_prime_orig;
    keygen(*ivrtree, &s_orig, &s_prime_orig);
    memcpy(&s, &s_orig, sizeof(s));
    memcpy(&s_prime, &s_prime_orig, sizeof(s_prime));
    
    
    memcpy(root_hashes[m_id].hash, (*ivrtree)[1].hash, HASH_LENGTH);
    
    
    
    Ptr<Packet> p;
    uint8_t size = 5+HASH_LENGTH;

    uint8_t *data = (uint8_t *)std::malloc (5+HASH_LENGTH);
    data[0] = intToChar(PKSHARE); 
    data[1] = ((m_id >> 24) & 0xFF); 
    data[2] = ((m_id >> 16) & 0xFF);
    data[3] = ((m_id >> 8) & 0xFF);
    data[4] = (m_id & 0xFF);
    
    memcpy(data+5, (*ivrtree)[1].hash, HASH_LENGTH);
    

    Send(data,size);
    std::free(data);
    
    
    
}



uint8_t*
DPoLNode::GenerateRandom(uint64_t& random_value){
  std::mt19937_64 rng(std::random_device{}());
  std::uniform_int_distribution<std::uint64_t> dist(0, UINT64_MAX);

  random_value = dist(rng);


  uint8_t *data = (uint8_t *)std::malloc (13);
  data[0] = intToChar(PREVOTE); 
  data[1] = intToChar((m_id >> 24) & 0xFF); 
  data[2] = intToChar((m_id >> 16) & 0xFF);
  data[3] = intToChar((m_id >> 8) & 0xFF);
  data[4] = intToChar(m_id & 0xFF);
  data[5] = intToChar((random_value >> 56) & 0xFF);
  data[6] = intToChar((random_value >> 48) & 0xFF);
  data[7] = intToChar((random_value >> 40) & 0xFF);
  data[8] = intToChar((random_value >> 32) & 0xFF);
  data[9] = intToChar((random_value >> 24) & 0xFF);
  data[10] = intToChar((random_value >> 16) & 0xFF);
  data[11] = intToChar((random_value >> 8) & 0xFF);
  data[12] = intToChar(random_value & 0xFF);
  
  return data;
}



void
DPoLNode::InitPrevote(void){
    
    
    
    
    uint32_t i_in=0, j_in=0;
    unsigned char v[HASH_LENGTH], y[HASH_LENGTH];
    std::vector<TREE_NODE> ap(LOGN);
    unsigned char mu1[MU_LENGTH]={0,}, mu2[MU_LENGTH]={0,};
		    
    unsigned char pk[OQS_SIG_falcon_512_length_public_key], sig[OQS_SIG_falcon_512_length_signature];
    size_t sig_len;
		    
    for (int i = 0; i < i_in; i++)
    {
        keyupd(&s, &s_prime);
    }

    unsigned char id[4];
    id[0] = (m_id >> 24) & 0xFF;
    id[1] = (m_id >> 16) & 0xFF;
    id[2] = (m_id >> 8) & 0xFF;
    id[3] = m_id & 0xFF;




    SHA256(id, sizeof(id), mu2);
    
    eval(v, y, ap, pk, sig, sig_len, mu1, mu2, i_in, j_in, &s, &s_prime, *ivrtree);


	
    size_t messageSize = 5 + HASH_LENGTH + HASH_LENGTH + 32 * LOGN + OQS_SIG_falcon_512_length_public_key + sig_len+sizeof(size_t);
    uint8_t* data = (uint8_t*)std::malloc(messageSize);
    
    size_t offset = 0;
    
    data[offset++] = intToChar(INITPREVOTE);

    data[offset++] = ((m_id >> 24) & 0xFF);
    data[offset++] = ((m_id >> 16) & 0xFF);
    data[offset++] = ((m_id >> 8) & 0xFF);
    data[offset++] = (m_id & 0xFF);
    
    
    uint8_t sig_len_bytes[sizeof(size_t)];
    
    for (size_t i = 0; i < sizeof(size_t); ++i) {
        sig_len_bytes[i] = intToChar((sig_len >> (i * 8)) & 0xFF);
        
    }
    
    
    memcpy(data + offset, sig_len_bytes, sizeof(size_t));
    offset += sizeof(size_t);
    
    memcpy(data + offset, v, HASH_LENGTH);
    offset += HASH_LENGTH;

    memcpy(data + offset, y, HASH_LENGTH);
    offset += HASH_LENGTH;

    memcpy(data + offset, ap.data(), 32 * LOGN);
    offset += 32 * LOGN;

    memcpy(data + offset, pk, OQS_SIG_falcon_512_length_public_key);
    offset += OQS_SIG_falcon_512_length_public_key;
    
    memcpy(data + offset, sig, sig_len);
    
    

    Send(data,messageSize);
    


    int verify_res = verify(mu1, mu2, i_in, j_in, v, y, ap, pk, sig, sig_len, &root_hashes[m_id]);
    
    if(verify_res==1){
	std::array<unsigned char, 32> arr;
	std::copy(std::begin(v), std::end(v), arr.begin());
        
	randomValues[m_id] = arr;
    }
		     
    
    free(data);

}


void
DPoLNode::Find_Minimum(Item item)
{
    const int k = producer_num;  

        min_heap.insert(item);
        if (min_heap.size() > k) {
            min_heap.erase(min_heap.begin());
        }

}




vector<uint8_t>
DPoLNode::GetBlockHash(Block block) {
    string str;
    
    for (int i = 0; i < network.prevHashSize; i++)  { str += block.header.prevHash[i]; }
    for (int i = 0; i < block.body.txs.size(); i++) { 
        for (int j = 0; j < block.body.txs[i].txItem.size(); j++)   { str += block.body.txs[i].txItem[j]; }
        for (int k = 0; k < block.body.txs[i].sign.size(); k++)     { str += block.body.txs[i].sign[k]; }
        for (int l = 0; l < block.body.txs[i].pk.size(); l++)       { str += block.body.txs[i].pk[l]; }
    }
    SHA sha;
    string temp;
    vector<uint8_t> blockHashValue;
    sha.update(str);
    temp = SHA::toString(sha.digest());
    for (int i = 0; i < network.prevHashSize; i++) { blockHashValue.push_back(temp[i]); }
    return blockHashValue;
}

vector<Tx>
DPoLNode::GetPendingTxs(void) {
        
        vector<Tx> newTxs;
        int txStorage = network.txStorage;
        int n=0;
        while(true) {

            if (m_memPool.empty()) { 
                cout << "Memory Pool is empty" << endl; 
                break;
            }

            Tx tx = m_memPool.front();
            int txSize = tx.GetTxSize();
            if (txSize <= txStorage) {
                m_memPool.pop();
                newTxs.push_back(tx);
                txStorage = txStorage - txSize;
            } else { break; }
            n++;
        }

       return newTxs;
    }
}
