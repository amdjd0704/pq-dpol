#ifndef BLOCK_H
#define BLOCK_H

#include <iostream>

#include <algorithm>


#include <map>

#include <queue>

#include <vector>

#include <iomanip>



using namespace std;

class Network;
class Blockchain;

class Block;

class Tx;

class Network {
        public:
            Network(void);
            ~Network(void);

            // ===== 함수 ===== //
            void                    PrintChain(string chainName, Blockchain chain);
            void                    PrintBlock(string blockName, Block block);
            void                    PrintVector(string vecName, vector<uint8_t> vec);
            void                    PrintIntVector(string vecName, vector<int> vec);
            void                    PrintTxs(string txName, vector<Tx> txs);
            uint8_t *               Block2Array(Block block);
            Block                   Array2Block(string packet);
            uint8_t *               Bytes2Packet(vector<uint8_t> vec, int vecSize);
            void                    Bytes2Array(vector<uint8_t> bytes, uint8_t * array);
            string                  Bytes2String(vector<uint8_t> bytes);
            void                    String2Array(string str, uint8_t *array);
            vector<uint8_t>         Array2Bytes(uint8_t arr[], int arrSize);



            float                   GetRandomDelay(void);                                       // 무작위 딜레이 값 계산 (Schedule의 Delay)

            // ===== 변수 ===== //
            int                 blockSize;
            int                 prevHashSize;
            int                 txStorage;

            int                 minimumWait;
            float               localAverage;
            float               zMax;
            int                 fastestNode;
            
            vector<int>         winNum;
            int                 numNodes;
            int                 numTxs;
            int                 maxTxItemSize;

    };


class Blockchain {

        public:

            Blockchain(void);

            ~Blockchain(void);



            // ===== 함수 ===== //

            void                    AddBlock(Block newBlock);

            int                     GetBlockchainHeight(void);

            Block                   GetLatestBlock(void);

            

            // ===== 변수 ===== //

            vector<Block>           blocks;

    };
class Block {

    public:

        Block(void);

        Block(vector<uint8_t> prevHash, vector<Tx> txs);
        
        ~Block(void);

        

        class BlockHeader {

            public:

                BlockHeader(void);

                BlockHeader(vector<uint8_t> prevHash); // 새로운 생성자 추가

                ~BlockHeader(void);

                

                // ===== 변수 ===== //

                vector<uint8_t>     prevHash;

        };



        class BlockBody {

            public:

                BlockBody(void);

                BlockBody(vector<Tx> txs); // 새로운 생성자 추가

                ~BlockBody(void);

                

                // ===== 변수 ===== //

                vector<Tx>     txs;

        };

        

        // ===== 함수 ===== //

        void SetHeader(vector<uint8_t> prevHash); // 함수 시그니처 수정
        void SetBody(vector<Tx> txs);



        pair<vector<uint8_t>, int>      SerializeBlock(void);

        pair<vector<uint8_t>, int>      SerializePrevHash(void);

        pair<vector<uint8_t>, int>      SerializeTxs(void);

        void                            DeserializeBlock(string packet);





        // ===== 변수 ===== //

        BlockHeader     header;

        BlockBody       body;

};




// ===================================================================================================================================================





    class Tx {

        public:

            Tx(void);

            Tx(vector<uint8_t> newTx);

            virtual ~Tx(void);



            void                            PrintTx(void);

            pair<vector<uint8_t>, int>      SerializeTx(void);

            void                            DeserializeTx(string packet);

            int                             GetTxSize(void);



            vector<uint8_t>                 txItem;

            vector<uint8_t>                 sign;

            vector<uint8_t>                 pk;

    };

#endif
