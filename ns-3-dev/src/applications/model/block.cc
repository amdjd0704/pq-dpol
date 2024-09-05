
#include "block.h"
#include "SHA.h"


using namespace std;




    Network::Network(void) {


        blockSize           = 500000;
        prevHashSize        = 64;
        txStorage           = blockSize - prevHashSize;
        
        winNum.assign(numNodes, 0);

    }

    Network::~Network(void) {
        // NS_LOG_FUNCTION(this);
    }

    // =============== 체인의 구성요소 출력 =============== //
    void
    Network::PrintChain(string chainName, Blockchain chain) {
        cout << endl;
        for(int i = 0; i < chain.GetBlockchainHeight(); i++) {
            string blockName = chainName + "'s [" + to_string(i) + "]th Block";
            PrintBlock(blockName, chain.blocks[i]);
            cout << endl;
        }
    }
    
    // =============== 블록의 구성요소 출력 =============== //
    void
    Network::PrintBlock(string blockName, Block block) {
        cout << blockName << ": ";
        cout << "{" << endl;
        PrintVector("   prevHash", block.header.prevHash);
        PrintTxs("   txs", block.body.txs);
        cout << "}" << endl;
    }

    // =============== 벡터의 구성요소 출력 (uint8_t) =============== //
    void
    Network::PrintVector(string vecName, vector<uint8_t> vec) {
        cout << vecName << ": ";
        for(int i = 0; i < vec.size(); i++) { cout << vec[i]; }
        cout << endl;
    }
    
    void
    Network::PrintTxs(string txName, vector<Tx> txs) {
        for (size_t i = 0; i < txs.size(); i++) { 
            cout << "   tx[" << i << "] { " << endl;
            txs[i].PrintTx(); 
        }
        cout << "}" << endl;
    }

    // =============== 벡터의 구성요소 출력 (int) =============== //
    void
    Network::PrintIntVector(string vecName, vector<int> vec) {
        cout << vecName << ": ";
        for(int i = 0; i < vec.size(); i++) { cout << vec[i]; }
        cout << endl;
    }

    // =============== Convert Bytes(vector) to Packet(array) =============== //  
    uint8_t *
    Network::Bytes2Packet(vector<uint8_t> vec, int vecSize) {
        uint8_t * packet = (uint8_t *)malloc((vecSize + 1) * sizeof(uint8_t));
        for (int i = 0; i < vecSize; i++) { packet[i] = vec[i]; }
        packet[vecSize] = '\0';

        return packet;
    }

    // =============== Convert Bytes(vector) to Array =============== //  
    void
    Network::Bytes2Array(vector<uint8_t> bytes, uint8_t * array) {
        const char *temp;
        char ch;

        string str = Bytes2String(bytes);
        for (size_t i = 0; i < str.size(); i += 2) {
            temp = str.substr(i, 2).c_str();
            ch = stoul(temp, NULL, 16);
            array[i/2] = ch;
        }

        // array[str.size()/2] = '\0';
    }

    // =============== Convert bytes to string =============== //
    string
    Network::Bytes2String(vector<uint8_t> vec) {
        string str = "";
        for (size_t i = 0; i < vec.size(); i++) { str += vec[i]; }

        return str;
    }

    void Network::String2Array(string str, uint8_t *array) {
        const char *temp;

        char ch;
        for (size_t i = 0; i < str.size(); i += 2) {
            temp = str.substr(i, 2).c_str();
            ch = stoul(temp, NULL, 16);
            array[i/2] = ch;
        }
    }

    // =============== Convert Array to Bytes(vector) =============== //  
    vector<uint8_t>
    Network::Array2Bytes(uint8_t arr[], int arrSize) {
        stringstream s;
        s << setfill('0') << hex;
        for (int i = 0; i < arrSize; i++)       { s << setw(2) << (unsigned int)arr[i]; }
        
        string str = s.str();
        vector<uint8_t> bytes;
        for (size_t i = 0; i < str.size(); i++)    { bytes.push_back(str[i]); }
        
        return bytes;
    }



Blockchain::Blockchain(void) {



    }



    // =============== Blockchain Class Destructor =============== //

    Blockchain::~Blockchain(void) {

        // NS_LOG_FUNCTION(this);

    }

    

    // =============== Add Block to Blockchain =============== //

    void

    Blockchain::AddBlock(Block newBlock) {

        this->blocks.push_back(newBlock);

    }



    // =============== Return the length of the chain =============== //

    int

    Blockchain::GetBlockchainHeight(void) {

        return this->blocks.size();

    }

    Block
    Blockchain::GetLatestBlock(void) {
        return this->blocks[this->GetBlockchainHeight() - 1];
    }



Block::Block(void) {
}

Block::Block(vector<uint8_t> prevHash, vector<Tx> txs) {
    this->SetHeader(prevHash);
    this->SetBody(txs);
}

Block::~Block(void) {
    // NS_LOG_FUNCTION(this);
}

void Block::SetHeader(vector<uint8_t> prevHash) {
    this->header.prevHash = prevHash;
}

void Block::SetBody(vector<Tx> txs) {
    this->body.txs = txs;
}

Block::BlockHeader::BlockHeader(void) {
    // NS_LOG_FUNCTION(this);
}

Block::BlockHeader::~BlockHeader(void) {
}

Block::BlockBody::BlockBody(void) {
}

Block::BlockBody::~BlockBody(void) {
    // NS_LOG_FUNCTION(this);
}

pair<vector<uint8_t>, int> Block::SerializeBlock(void) {
    vector<uint8_t> serializedPrevHash = this->SerializePrevHash().first;
    vector<uint8_t> serializedTxs = this->SerializeTxs().first;
    
    int serializedPrevHashSize = this->SerializePrevHash().second;
    int serializedTxsSize = this->SerializeTxs().second;

    vector<uint8_t> serializedBlock;
    serializedBlock.push_back('/');
    serializedBlock.push_back('b');
    
    for (int i = 0; i < serializedPrevHashSize; i++)    { serializedBlock.push_back(serializedPrevHash[i]); }
    for (int i = 0; i < serializedTxsSize; i++)         { serializedBlock.push_back(serializedTxs[i]); }
    
    
    
    return make_pair(serializedBlock, serializedBlock.size());
}

pair<vector<uint8_t>, int> Block::SerializePrevHash(void) {
    vector<uint8_t> serializedPrevHash;
    
    serializedPrevHash.push_back('/');
    serializedPrevHash.push_back('h');
    for (size_t i = 0; i < this->header.prevHash.size(); i++) { serializedPrevHash.push_back(this->header.prevHash[i]); }

    return make_pair(serializedPrevHash, serializedPrevHash.size());
}

pair<vector<uint8_t>, int> Block::SerializeTxs(void) {
    vector<uint8_t> serializedTxs;

    for (size_t i = 0; i < this->body.txs.size(); i++) { 
        vector<uint8_t> serializedTx = this->body.txs[i].SerializeTx().first;
        int serializedTxSize = this->body.txs[i].SerializeTx().second;
        for (int j = 0; j < serializedTxSize; j++) { 
            serializedTxs.push_back(serializedTx[j]); 
        }
    }

    return make_pair(serializedTxs, serializedTxs.size());
}

// =============== Deserialize Block =============== //
void Block::DeserializeBlock(string packet) {
    char offset = NULL;
    int idx = -1;
    int i = -1;

    do {
        i++;
        if (packet[i] == '/') {
            if      (packet[i + 1] == 'b')  { offset = 'b'; i++;                                             continue; } // 'b'lock
            else if (packet[i + 1] == 'h')  { offset = 'h'; i++;                                             continue; } // prev'h'ash
            else if (packet[i + 1] == 'x')  { offset = 'x'; i++; idx++; Tx tx; this->body.txs.push_back(tx); continue; } // t'x'
            else if (packet[i + 1] == 'k')  { offset = 'k'; i++;                                             continue; } // 'k'ey
            else if (packet[i + 1] == 's')  { offset = 's'; i++;                                             continue; } // 's'ign
            
        } else if (packet[i] == '\0') { break; }

        switch(offset) {
            // 'b'lock
            case 'b':
                continue;

            // prev'h'ash
            case 'h':
                this->header.prevHash.push_back(packet[i]);
                continue;

            // t'x'
            case 'x':
                this->body.txs[idx].txItem.push_back(packet[i]);
                continue;
                
            // 'k'ey
            case 'k':
                this->body.txs[idx].pk.push_back(packet[i]);
                continue;

            // 's'ign
            case 's':
                this->body.txs[idx].sign.push_back(packet[i]);
                continue;

        }
    } while(i != packet.size());
}

// ===================================================================================================================================================



    // =============== Tx Constructor =============== //

    Tx::Tx(void) {



    }



    // =============== Tx Destructor =============== //

    Tx::~Tx(void) {

        // NS_LOG_FUNCTION(this);

    }





    // void                            

    // Tx::PrintTx(void) {



    // }



    pair<vector<uint8_t>, int>      

    Tx::SerializeTx(void) {

        vector<uint8_t> serializedTx;



        serializedTx.push_back('/');

        serializedTx.push_back('x');

        for (size_t i = 0; i < this->txItem.size(); i++) { serializedTx.push_back(this->txItem[i]); }

         

        serializedTx.push_back('/');

        serializedTx.push_back('s');

        for (size_t i = 0; i < this->sign.size(); i++) { serializedTx.push_back(this->sign[i]); }



        serializedTx.push_back('/');

        serializedTx.push_back('k');

        for (size_t i = 0; i < this->pk.size(); i++) { serializedTx.push_back(this->pk[i]); }



        return make_pair(serializedTx, serializedTx.size());

    }



    // void                            

    // Tx::DeserializeTx(string packet) {



    // }



    int                             

    Tx::GetTxSize(void) {

        return this->txItem.size() + this->sign.size() + this->pk.size();

    }



    // =============== Print Transactions =============== //

    void

    Tx::PrintTx(void) {

        cout << "       txItem: ";

        for (size_t i = 0; i < this->txItem.size(); i++)   { cout << this->txItem[i]; }

        cout << endl;

        cout << "       sign: ";

        for (size_t i = 0; i < this->sign.size(); i++)     { cout << this->sign[i]; }

        cout << endl;

        cout << "       pk: ";

        for (size_t i = 0; i < this->pk.size(); i++)       { cout << this->pk[i]; }

        cout << endl;

    }



