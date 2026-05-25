// ============================================================
// HOW TO COMPILE & RUN  (from d:\voting\ in PowerShell)
// ============================================================
// STEP 1 - Compile:
//   $env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH; g++ voting.cpp -o voting.exe -I"C:/msys64/mingw64/include" -L"C:/msys64/mingw64/lib" -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32
//
// STEP 2 - Run:
//   .\core.exe
// ============================================================


#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/aes.h>

using namespace std;

// Constants
const string INTERNAL_KEY = "voting_system_key_2024";
const string ADMIN_ID = "admin";
const string ADMIN_PASS = "system";
const string AGENT_ID = "agent";
const string AGENT_PASS = "agentpass";

// Forward declarations
class Blockchain;
class Wallet;
void save_blockchain(vector<unsigned char> data);
string calculate_hash(int index, string data, string previoushash, string timestamp, int nonce);
bool validate_voter_credentials(string id, string fp, string file_path);

// --- SECURITY HELPERS ---

string calculate_hash(int index, string data, string previoushash, string timestamp, int nonce) 
{
    string input = to_string(index) + data + previoushash + timestamp + to_string(nonce);
    long long hash = 0;
    for (char c : input) {
        hash = (hash * 71 + c) % 1000000009;
    }
    return to_string(hash);
}

vector<unsigned char> aes_encrypt(string data, string key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0};
    unsigned char keyBytes[16] = {0};
    for (int i = 0; i < (int)key.size() && i < 16; i++)
        keyBytes[i] = key[i];

    vector<unsigned char> output(data.size() + 16);
    int len = 0, totalLen = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyBytes, iv) != 1) return {};
    if (EVP_EncryptUpdate(ctx, output.data(), &len, (unsigned char*)data.c_str(), (int)data.size()) != 1) return {};
    totalLen = len;
    if (EVP_EncryptFinal_ex(ctx, output.data() + len, &len) != 1) return {};
    totalLen += len;
    EVP_CIPHER_CTX_free(ctx);
    output.resize(totalLen);
    return output;
}

string aes_decrypt(vector<unsigned char> data, string key) {
    if (data.empty()) return "DECRYPT_ERROR";
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0};
    unsigned char keyBytes[16] = {0};
    for (int i = 0; i < (int)key.size() && i < 16; i++)
        keyBytes[i] = key[i];

    vector<unsigned char> output(data.size() + 16);
    int len = 0, totalLen = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyBytes, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "DECRYPT_ERROR";
    }
    if (EVP_DecryptUpdate(ctx, output.data(), &len, data.data(), (int)data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "DECRYPT_ERROR";
    }
    totalLen = len;
    if (EVP_DecryptFinal_ex(ctx, output.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "DECRYPT_ERROR";
    }
    totalLen += len;
    EVP_CIPHER_CTX_free(ctx);
    return string(output.begin(), output.begin() + totalLen);
}

string get_public_key(string secret) 
{
    return "PUB_" + calculate_hash(0, secret, "VOTING_ROOT", "STABLE_ID", 0);
}

// --- CORE BLOCKCHAIN STRUCTURES ---

struct Node {
    int index;
    vector<unsigned char> data;
    string previoushash;
    string hash;
    string timestamp;
    int nonce;
    Node* next;

    Node(int idx, vector<unsigned char> d, string prev_h) : index(idx), data(d), previoushash(prev_h), next(nullptr), nonce(0) {
        time_t now = time(0);
        char* dt = ctime(&now);
        timestamp = string(dt);
        if (!timestamp.empty() && timestamp.back() == '\n') timestamp.pop_back();

        string dataStr(data.begin(), data.end());
        hash = calculate_hash(index, dataStr, previoushash, timestamp, nonce);
    }
};

class Blockchain {
private:
    Node* head;
    Node* tail;
    int size;
    bool loading;
    string voter_file_path;

public:
    Blockchain() : head(nullptr), tail(nullptr), size(0), loading(false), voter_file_path("voters.txt") {}

    string get_voter_file_path() { return voter_file_path; }

    void set_voter_file_path(const string& path) {
        cout << "[DEBUG] Starting set_voter_file_path" << endl;
        voter_file_path = path;
        // Persist the new path to the blockchain
        string record = "CONFIG|VOTER_FILE|" + path;
        vector<unsigned char> data(record.begin(), record.end());
        cout << "[DEBUG] Inserting CONFIG block" << endl;
        insert_block(data);
        cout << "[DEBUG] Finished set_voter_file_path" << endl;
    }

    void insert_block(vector<unsigned char> encryptedData) {

        string prevH = (tail) ? tail->hash : "0";
        Node* newNode = new Node(size, encryptedData, prevH);

        // 🔥 ONLY DO MINING WHEN NOT LOADING
        if (!loading) {
            string dataStr(encryptedData.begin(), encryptedData.end());
            long long target = 900000000; //Fix v2

            while (stoll(newNode->hash) > target) {
                newNode->nonce++;
                newNode->hash = calculate_hash(
                    newNode->index,
                    dataStr,
                    newNode->previoushash,
                    newNode->timestamp,
                    newNode->nonce
                );
            }
        }

        // Insert into chain
        if (!head) {
            head = tail = newNode;
        } else {
            tail->next = newNode;
            tail = newNode;
        }

        size++;

        // 🔥 ONLY SAVE WHEN NOT LOADING
        if (!loading) {
            save_blockchain_to_disk(encryptedData);
        }
    }

    void save_blockchain_to_disk(vector<unsigned char> blockData) {
        cout << "[DEBUG] save_blockchain_to_disk start" << endl;
        string plain(blockData.begin(), blockData.end());
        vector<unsigned char> encrypted = aes_encrypt(plain, INTERNAL_KEY);
        cout << "[DEBUG] aes_encrypt done, opening file" << endl;
        ofstream file("election_data.enc", ios::app | ios::binary);
        int s = (int)encrypted.size();
        file.write((char*)&s, sizeof(s));
        file.write((char*)encrypted.data(), s);
        file.flush(); // V2 Fix
        file.close();
        cout << "[DEBUG] save_blockchain_to_disk end" << endl;
    }

    void load_blockchain() {
        ifstream file("election_data.enc", ios::binary);
        if (!file.is_open()) {
            cout << ">>> No existing data file found. Starting fresh." << endl;
            return;
        }
        head = nullptr; //Added on v2
        tail = nullptr; //Added on v2
        size = 0; //Added on v2
        loading = true;
        int blocks_loaded = 0;
        while (true) {
            int s = 0;
            if (!file.read((char*)&s, sizeof(s))) break;
            if (s <= 0 || s > 10000000) {
                cerr << ">>> [WARNING] Corrupt entry detected. Stopping at block " << blocks_loaded << endl;
                break;
            }
            vector<unsigned char> encrypted(s);
            if (!file.read((char*)encrypted.data(), s)) break;
            string decrypted = aes_decrypt(encrypted, INTERNAL_KEY);
            if (decrypted == "DECRYPT_ERROR") continue;
            // Restore voter file path config without re-inserting to chain
            if (decrypted.find("CONFIG|VOTER_FILE|") == 0) {
                voter_file_path = decrypted.substr(18);
            }
            vector<unsigned char> blockData(decrypted.begin(), decrypted.end());
            insert_block(blockData);
            blocks_loaded++;
        }
        loading = false;
        file.close();
        if (blocks_loaded > 0) {
            cout << ">>> [OK] Encrypted data loaded from election_data.enc" << endl;
            print_summary();
        }
    }

    void print_summary() {
        int voters = 0, accounts = 0, options = 0, votes = 0;
        
        // Count total eligible voters from the configured voter file
        ifstream file(voter_file_path);
        if (file.is_open()) 
        {
            string line_id, line_fp;
            while (file >> line_id >> line_fp) 
            {
                voters++;
            }
            file.close();
        }

        Node* curr = head;
        while (curr) {
            string dec(curr->data.begin(), curr->data.end());
            if (dec.find("VOTER_ACCOUNT|") == 0) accounts++;
            else if (dec.find("OPTION|") == 0) options++;
            else if (dec.find("ANONYMOUS_VOTE|") == 0) votes++;
            curr = curr->next;
        }
        cout << ">>> Eligible Voters   : " << voters << " (From: " << voter_file_path << ")" << endl;
        cout << ">>> Voter Accounts    : " << accounts << endl;
        cout << ">>> Candidates        : " << options << endl;
        cout << ">>> Votes Cast        : " << votes << endl;
    }

    Node* getHead() 
    { 
        return head; 
    }

    bool is_voter_allowed(string voterNumHash) {
        Node* curr = head;
        while (curr) {
            string dec(curr->data.begin(), curr->data.end());
            if (dec.find("ALLOWED_VOTER|") == 0) {
                if (dec.substr(14) == voterNumHash) return true;
            }
            curr = curr->next;
        }
        return false;
    }

    bool is_voter_used(string voterNumHash) {
        Node* curr = head;
        while (curr) {
            string dec(curr->data.begin(), curr->data.end());
            if (dec.find("VOTER_ACCOUNT|") == 0) {
                size_t firstPipe = dec.find("|");
                size_t secondPipe = dec.find("|", firstPipe + 1);
                if (dec.substr(firstPipe + 1, secondPipe - firstPipe - 1) == voterNumHash) return true;
            }
            curr = curr->next;
        }
        return false;
    }

    vector<string> get_options() {
        vector<string> options;
        Node* curr = head;
        while (curr) {
            string dec(curr->data.begin(), curr->data.end());
            if (dec.find("OPTION|") == 0) {
                options.push_back(dec.substr(7));
            }
            curr = curr->next;
        }
        return options;
    }

    bool has_voted(string public_key) {
        Node* curr = head;
        while (curr) {
            string dec(curr->data.begin(), curr->data.end());
            if (dec.find("HAS_VOTED|") == 0) {
                if (dec.substr(10) == public_key) return true;
            }
            curr = curr->next;
        }
        return false;
    }

    string get_public_address_from_hash(string voterNumHash) {
        Node* curr = head;
        while (curr) {
            string dec(curr->data.begin(), curr->data.end());
            if (dec.find("VOTER_ACCOUNT|") == 0) {
                size_t firstPipe = dec.find("|");
                size_t secondPipe = dec.find("|", firstPipe + 1);
                if (dec.substr(firstPipe + 1, secondPipe - firstPipe - 1) == voterNumHash) {
                    string rest = dec.substr(secondPipe + 1);
                    size_t thirdPipe = rest.find("|");
                    if (thirdPipe != string::npos) {
                        return rest.substr(0, thirdPipe);
                    }
                    return rest;
                }
            }
            curr = curr->next;
        }
        return "";
    }

    // Returns the stored encrypted fingerprint hash for a given voter number hash
    string get_fingerprint_hash_from_voter(string voterNumHash) {
        Node* curr = head;
        while (curr) {
            string dec(curr->data.begin(), curr->data.end());
            if (dec.find("VOTER_ACCOUNT|") == 0) {
                size_t p1 = dec.find("|");
                size_t p2 = dec.find("|", p1 + 1);
                size_t p3 = dec.find("|", p2 + 1);
                if (dec.substr(p1 + 1, p2 - p1 - 1) == voterNumHash) {
                    if (p3 != string::npos) {
                        return dec.substr(p3 + 1); // encrypted fingerprint hash
                    }
                }
            }
            curr = curr->next;
        }
        return "";
    }

    bool get_latest_otp(string public_key, string& out_otp, time_t& out_time) {
        bool found = false;
        Node* curr = head;
        while (curr) {
            string dec(curr->data.begin(), curr->data.end());
            if (dec.find("OTP|") == 0) {
                size_t firstPipe = dec.find("|");
                size_t secondPipe = dec.find("|", firstPipe + 1);
                string pb = dec.substr(firstPipe + 1, secondPipe - firstPipe - 1);
                if (pb == public_key) {
                    size_t thirdPipe = dec.find("|", secondPipe + 1);
                    out_otp = dec.substr(secondPipe + 1, thirdPipe - secondPipe - 1);
                    string ts_str = dec.substr(thirdPipe + 1);
                    out_time = stoll(ts_str);
                    found = true;
                }
            }
            curr = curr->next;
        }
        return found;
    }

    void factory_reset() {
        Node* curr = head;
        while (curr) {
            Node* temp = curr;
            curr = curr->next;
            delete temp;
        }
        head = nullptr;
        tail = nullptr;
        size = 0;
        
        ofstream erase("election_data.enc", ios::trunc | ios::binary);
        erase.close();
        
        cout << ">>> [SUCCESS] Factory Reset complete. Blockchain and secure file have been WIPED completely." << endl;
    }

    void reset_votes() {
        vector<vector<unsigned char>> to_keep;
        Node* curr = head;
        while (curr) {
            string dec(curr->data.begin(), curr->data.end());
            if (dec.find("ANONYMOUS_VOTE|") != 0 && dec.find("HAS_VOTED|") != 0 && dec.find("OTP|") != 0) {
                to_keep.push_back(curr->data);
            }
            curr = curr->next;
        }

        // Wipe memory
        curr = head;
        while (curr) {
            Node* temp = curr;
            curr = curr->next;
            delete temp;
        }
        head = tail = nullptr;
        size = 0;

        // Wipe disk file
        ofstream erase("election_data.enc", ios::trunc | ios::binary);
        erase.close();

        // Reinsert valid blocks normally (saving immediately)
        for (const auto& data : to_keep) {
            insert_block(data);
        }
        
        cout << ">>> [SUCCESS] All Votes and OTPs have been cleared. Candidates and Voter Accounts remain." << endl;
    }

    void reset_candidates_and_votes() {
        vector<vector<unsigned char>> to_keep;
        Node* curr = head;
        while (curr) {
            string dec(curr->data.begin(), curr->data.end());
            // Keep everything except VOTES, OTPs, and OPTIONS/CANDIDATES
            if (dec.find("ANONYMOUS_VOTE|") != 0 && dec.find("HAS_VOTED|") != 0 && dec.find("OTP|") != 0 && dec.find("OPTION|") != 0 && dec.find("ALLOWED_VOTER|") != 0) { 
                to_keep.push_back(curr->data);
            }
            curr = curr->next;
        }

        // Wipe memory
        curr = head;
        while (curr) {
            Node* temp = curr;
            curr = curr->next;
            delete temp;
        }
        head = tail = nullptr;
        size = 0;

        // Wipe disk file
        ofstream erase("election_data.enc", ios::trunc | ios::binary);
        erase.close();

        // Reinsert valid blocks normally
        for (const auto& data : to_keep) {
            insert_block(data);
        }
        
        cout << ">>> [SUCCESS] All Candidates, Votes, and OTPs have been cleared. Voter Accounts remain." << endl;
    }
    void clear_voter_data() {
        cout << "[DEBUG] Starting clear_voter_data" << endl;
        vector<vector<unsigned char>> to_keep;
        Node* curr = head;
        while (curr) {
            string dec(curr->data.begin(), curr->data.end());
            if (dec.find("ALLOWED_VOTER|") != 0 && 
                dec.find("VOTER_ACCOUNT|") != 0 && 
                dec.find("HAS_VOTED|") != 0 && 
                dec.find("OTP|") != 0 &&
                dec.find("ANONYMOUS_VOTE|") != 0) {
                to_keep.push_back(curr->data);
            }
            curr = curr->next;
        }

        cout << "[DEBUG] Memory wiping" << endl;
        curr = head;
        while (curr) {
            Node* temp = curr;
            curr = curr->next;
            delete temp;
        }
        head = tail = nullptr;
        size = 0;

        cout << "[DEBUG] File wiping" << endl;
        ofstream erase("election_data.enc", ios::trunc | ios::binary);
        erase.close();

        cout << "[DEBUG] Reinserting " << to_keep.size() << " blocks" << endl;
        for (const auto& data : to_keep) {
            insert_block(data);
        }
        
        cout << ">>> [INFO] Previous voter list and election state cleared. Ready for new file." << endl;
    }
};

// --- WALLET / USER CLASS ---

class Wallet {
public:
    string secret;
    string public_address;

    Wallet(string sec) : secret(sec) {
        public_address = get_public_key(secret);
    }
};

// --- CREDENTIAL VALIDATION ---
bool validate_voter_credentials(string id, string fp, string file_path) {
    ifstream file(file_path);
    if (!file.is_open()) {
        cout << ">>> [ERROR] Cannot open voter file: " << file_path << endl;
        return false;
    }
    string line_id, line_fp;
    while (file >> line_id >> line_fp) {
        if (line_id == id && line_fp == fp) {
            file.close();
            return true;
        }
    }
    file.close();
    return false;
}

// --- SYSTEM FUNCTIONS ---

void admin_panel(Blockchain& bc) {
    string user, pass;
    cout << "\n--- Admin Login ---" << endl;
    cout << "ID: "; cin >> user;
    cout << "Password: "; cin >> pass;

    if (user != ADMIN_ID || pass != ADMIN_PASS) {
        cout << ">>> Login Failed!" << endl;
        return;
    }

    while (true) {
        cout << "\n========== ADMIN DASHBOARD ==========" << endl;
        cout << "1. Load Voter Numbers from File" << endl;
        cout << "2. Add Voting Option (Candidate)" << endl;
        cout << "3. View Results" << endl;
        cout << "4. Advanced System Reset" << endl;
        cout << "5. Logout" << endl;
        cout << "Choice: ";
        
        int choice; 
        if (!(cin >> choice)) {
            cin.clear(); cin.ignore(10000, '\n'); continue;
        }

        if (choice == 1) {
            string path;
            cout << "Enter voter file path (e.g. voters.txt or C:\\path\\to\\file.txt): ";
            cin.ignore(10000, '\n');
            getline(cin, path);
            // Trim whitespace/quotes
            while (!path.empty() && (path.front() == '"' || path.front() == ' ')) path.erase(path.begin());
            while (!path.empty() && (path.back()  == '"' || path.back()  == ' ')) path.pop_back();

            ifstream file(path);
            if (!file.is_open()) {
                cout << ">>> [ERROR] Cannot open file: '" << path << "'. Please check the path." << endl;
            } else {
                // Clear previous voter data to replace with new file only
                bc.clear_voter_data();

                // Update the dynamic file path in blockchain (persisted as CONFIG block)
                bc.set_voter_file_path(path);
                cout << ">>> [OK] Voter file set to: " << path << endl;

                string voterNum, fp;
                int count = 0;
                cout << "[DEBUG] Starting to read voter file" << endl;
                while (file >> voterNum >> fp) {
                    cout << "[DEBUG] Read: " << voterNum << ", " << fp << endl;
                    string h = calculate_hash(0, voterNum, "VOTER_SALT", "", 0);
                    if (!bc.is_voter_allowed(h)) {
                        string record = "ALLOWED_VOTER|" + h;
                        vector<unsigned char> data(record.begin(), record.end());
                        bc.insert_block(data);
                        count++;
                    }
                }
                cout << ">>> Added " << count << " new voter entries from '" << path << "'." << endl;
                file.close();
            }
        } else if (choice == 2) {
            string option;
            cout << "Enter Candidate Name: ";
            cin.ignore(10000, '\n');
            getline(cin, option);
            string record = "OPTION|" + option;
            vector<unsigned char> data(record.begin(), record.end());
            bc.insert_block(data);
            cout << ">>> Candidate '" << option << "' saved to election_data.enc (encrypted)." << endl;
        } else if (choice == 3) {
            bc.load_blockchain(); // V2 Fix
            vector<string> options = bc.get_options();
            if (options.empty()) {
                cout << "No candidates added yet." << endl;
            } else {
                cout << "\n--- Current Standings ---" << endl;
                for (string opt : options) {
                    int count = 0;
                    string opt_hash = calculate_hash(0, opt, "VOTE_SALT", "", 0);
                    Node* curr = bc.getHead();
                    while (curr) {
                        string dec(curr->data.begin(), curr->data.end());
                        if (dec.find("ANONYMOUS_VOTE|") == 0) {
                            if (dec.substr(15) == opt_hash) count++;
                        }
                        curr = curr->next;
                    }
                    cout << opt << ": " << count << " votes" << endl;
                }
            }
        } else if (choice == 4) {
            cout << "\n!!! DANGER ZONE !!!" << endl;
            cout << "1. Only Reset Votes (Delete Votes and OTPs. Keep Candidates and Accounts)" << endl;
            cout << "2. Factory Reset (Wipe EVERYTHING. Starts completely fresh)" << endl;
            cout << "3. Reset Candidates & Votes (Delete Candidates, Votes, OTPs. Keep Accounts)" << endl;
            cout << "4. Cancel" << endl;
            cout << "Choice: ";
            int resChoice;
            if (!(cin >> resChoice)) {
                cin.clear(); cin.ignore(10000, '\n'); continue;
            }
            if (resChoice == 1) {
                cout << "Are you absolutely sure you want to delete all votes? (y/n): ";
                char confirm; cin >> confirm;
                if (confirm == 'y' || confirm == 'Y') {
                    bc.reset_votes();
                }
            } else if (resChoice == 2) {
                cout << "Are you absolutely sure you want to WIPE THE ENTIRE BLOCKCHAIN? (y/n): ";
                char confirm; cin >> confirm;
                if (confirm == 'y' || confirm == 'Y') {
                    bc.factory_reset();
                }
            } else if (resChoice == 3) {
                cout << "Are you sure you want to delete all candidates AND votes? (y/n): ";
                char confirm; cin >> confirm;
                if (confirm == 'y' || confirm == 'Y') {
                    bc.reset_candidates_and_votes();
                }
            }
        } else if (choice == 5) {
            break;
        }
    }
}

void polling_agent_panel(Blockchain& bc) {
    bc.load_blockchain(); //V2 Fix
    string user, pass;
    cout << "\n--- Polling Agent Login ---" << endl;
    cout << "ID: "; cin >> user;
    cout << "Password: "; cin >> pass;

    if (user != AGENT_ID || pass != AGENT_PASS) {
        cout << ">>> Login Failed!" << endl;
        return;
    }

    while (true) {
        cout << "\n========== POLLING AGENT DASHBOARD ==========" << endl;
        cout << "1. Issue 5-Min OTP for Voter" << endl;
        cout << "2. Logout" << endl;
        cout << "Choice: ";
        int choice; cin >> choice;

        if (choice == 1) {
             bc.load_blockchain(); // v2 fix
            string voterNum;
            cout << "Enter Voter Number: ";
            cin >> voterNum;

            string h = calculate_hash(0, voterNum, "VOTER_SALT", "", 0);
            if (!bc.is_voter_used(h)) {
                cout << ">>> [ERROR] Voter has not registered an account yet!" << endl;
                continue;
            }

            // Verify voter's fingerprint before issuing OTP
            string fingerprint_input;
            cout << "Enter Voter Fingerprint (4-digit) for verification: ";
            cin >> fingerprint_input;
            string enc_fp_input = calculate_hash(0, fingerprint_input, "FINGERPRINT_ENC", "", 0);
            string stored_fp_hash = bc.get_fingerprint_hash_from_voter(h);

            if (stored_fp_hash.empty() || enc_fp_input != stored_fp_hash) {
                cout << ">>> [DENIED] Fingerprint does not match voter record! OTP not issued." << endl;
                cout << ">>> The real voter must be physically present to receive an OTP." << endl;
                continue;
            }
            cout << ">>> [OK] Fingerprint verified. Proceeding to issue OTP..." << endl;

            string pub_addr = bc.get_public_address_from_hash(h);
            if (pub_addr.empty()) {
                cout << ">>> [ERROR] Could not find Voter address." << endl;
                continue;
            }

            string existing_otp;
            time_t existing_time;
            if (bc.get_latest_otp(pub_addr, existing_otp, existing_time)) {
                if (time(0) - existing_time <= 300) {
                    cout << ">>> [DENIED] An active OTP has already been generated for this voter!" << endl;
                    cout << ">>> Please wait for the current OTP to expire before generating a new one." << endl;
                    continue;
                } else {
                    cout << ">>> [INFO] Previous OTP expired. Generating a new one..." << endl;
                }
            }

            // Generate 6-digit OTP
            string characters = "0123456789";
            string otp = "";
            srand(time(0) + rand());
            for (int i = 0; i < 6; i++) {
                otp += characters[rand() % characters.length()];
            }

            time_t now = time(0);
            string record = "OTP|" + pub_addr + "|" + otp + "|" + to_string(now);
            vector<unsigned char> data(record.begin(), record.end());
            bc.insert_block(data);

            cout << ">>> [SUCCESS] Generated OTP: " << otp << endl;
            cout << ">>> This OTP is valid for exactly 5 minutes (300 seconds) for this voter." << endl;
            cout << ">>> Encrypted save to election_data.enc completed." << endl;
        } else if (choice == 2) {
            break;
        }
    }
}

void user_registration(Blockchain& bc) {
    bc.load_blockchain(); // V2 Fix
    string voterNum;
    cout << "\n--- Voter Registration ---" << endl;
    cout << "Enter your Voter Number: ";
    cin >> voterNum;

    string fingerprint;
    cout << "Enter Fingerprint (4-digit): ";
    cin >> fingerprint;

    if (!validate_voter_credentials(voterNum, fingerprint, bc.get_voter_file_path())) {
        cout << ">>> [ERROR] Voter ID and Fingerprint do not match our records!" << endl;
        return;
    }

    string h = calculate_hash(0, voterNum, "VOTER_SALT", "", 0);
    if (!bc.is_voter_allowed(h)) {
        cout << ">>> [ERROR] Voter is not allowed to register. Admin must load voter numbers first!" << endl;
        return;
    }

    if (bc.is_voter_used(h)) {
        cout << ">>> [ERROR] Account already created for this Voter Number!" << endl;
        return;
    }

    // Encrypt the fingerprint before storing it in the blockchain
    string enc_fingerprint = calculate_hash(0, fingerprint, "FINGERPRINT_ENC", "", 0);
    
    // Generate Secret Key
    string secret = "SEC_" + calculate_hash(0, voterNum, "USER_LOGIN_SALT", to_string(time(0)), 0);
    Wallet* w = new Wallet(secret);
    
    // Save to chain
    string record = "VOTER_ACCOUNT|" + h + "|" + w->public_address + "|" + enc_fingerprint;
    vector<unsigned char> data(record.begin(), record.end());
    bc.insert_block(data);

    cout << "\n>>> [SUCCESS] Voter Account Created!" << endl;
    cout << ">>> Your PUBLIC ADDRESS and ENCRYPTED FINGERPRINT were securely saved to the blockchain (election_data.enc)." << endl;
    cout << "\n==============================================" << endl;
    cout << ">>> YOUR SECRET KEY: " << secret << endl;
    cout << "==============================================" << endl;
    cout << ">>> IMPORTANT: This Secret Key is NEVER saved in the blockchain!" << endl;
    cout << ">>> If you lose it, you lose access to your account permanently." << endl;

    char saveOption;
    cout << "Would you like to save your Voter Details to a local text file? (y/n): ";
    cin >> saveOption;
    if (saveOption == 'y' || saveOption == 'Y') {
        string filename;
        cout << "Enter filename to save as (e.g. key.txt): ";
        cin >> filename;
        ofstream outFile(filename);
        if (outFile.is_open()) {
            outFile << "======================================\n";
            outFile << "          VOTER CREDENTIALS           \n";
            outFile << "======================================\n";
            outFile << "Voter Number: " << voterNum << "\n";
            outFile << "Secret Key:   " << secret << "\n";
            outFile << "Fingerprint:  " << fingerprint << "\n";
            outFile << "--------------------------------------\n";
            outFile << "IMPORTANT: Do not share this file!\n";
            outFile.close();
            cout << ">>> [SUCCESS] Details saved to '" << filename << "'!" << endl;
        } else {
            cout << ">>> [ERROR] Could not save to file." << endl;
        }
    }
}

void user_login(Blockchain& bc) {
    bc.load_blockchain(); //V2 fix
    string secret, fingerprint;
    cout << "\n--- Voter Login ---" << endl;
    cout << "Enter Secret Key: ";
    cin >> secret;
    cout << "Enter Demo Fingerprint (digit/pass): ";
    cin >> fingerprint;

    string pub = get_public_key(secret);
    string enc_fingerprint = calculate_hash(0, fingerprint, "FINGERPRINT_ENC", "", 0);
    
    bool exists = false;
    Node* curr = bc.getHead();
    while (curr) {
        string dec(curr->data.begin(), curr->data.end());
        if (dec.find("VOTER_ACCOUNT|") == 0) {
            size_t firstPipe = dec.find("|");
            size_t secondPipe = dec.find("|", firstPipe + 1);
            size_t thirdPipe = dec.find("|", secondPipe + 1);

            if (thirdPipe != string::npos) {
                string saved_pub = dec.substr(secondPipe + 1, thirdPipe - secondPipe - 1);
                string saved_fp = dec.substr(thirdPipe + 1);
                
                if (saved_pub == pub && saved_fp == enc_fingerprint) {
                    exists = true;
                    break;
                }
            } else {
                // Backward compatibility for old accounts without fingerprint
                string saved_pub = dec.substr(secondPipe + 1);
                if (saved_pub == pub) {
                    exists = true;
                    break;
                }
            }
        }
        curr = curr->next;
    }

    if (!exists) {
        cout << ">>> [ERROR] Invalid Secret Key, Incorrect Fingerprint, or Account not registered!" << endl;
        return;
    }

    cout << ">>> Login Successful!" << endl;

    while (true) {
        cout << "\n---------- VOTER DASHBOARD ----------" << endl;
        cout << "1. Cast Vote" << endl;
        cout << "2. View Candidates" << endl;
        cout << "3. Save My Credentials to File" << endl;
        cout << "4. Logout" << endl;
        cout << "Choice: ";
        int choice; cin >> choice;

        if (choice == 1) {
            if (bc.has_voted(pub)) {
                cout << ">>> [DENIED] You have already cast your vote!" << endl;
                continue;
            }
             // REAL-TIME FIX
            bc.load_blockchain(); //V2 fix

            string entered_otp;
            cout << "Enter 6-digit Polling Agent OTP: ";
            cin >> entered_otp;

            string valid_otp;
            time_t otp_time;
            if (!bc.get_latest_otp(pub, valid_otp, otp_time)) {
                cout << ">>> [DENIED] No OTP found for your account. Please see a Polling Agent." << endl;
                continue;
            }
            if (entered_otp != valid_otp) {
                cout << ">>> [DENIED] Incorrect OTP! Please verify with the Polling Agent." << endl;
                continue;
            }
            if (time(0) - otp_time > 300) {
                cout << ">>> [DENIED] OTP has expired (Valid for 5 minutes only). Please see the Polling Agent for a new one." << endl;
                continue;
            }

            vector<string> options = bc.get_options();
            if (options.empty()) {
                cout << "No candidates available to vote for." << endl;
            } else {
                cout << "\nSelect Candidate:" << endl;
                for (int i = 0; i < (int)options.size(); i++) {
                    cout << i + 1 << ". " << options[i] << endl;
                }
                int v; cin >> v;
                if (v > 0 && v <= (int)options.size()) {
                    string opt_hash = calculate_hash(0, options[v - 1], "VOTE_SALT", "", 0);
                    
                    // 1. Mark as voted (Identity block)
                    string voted_record = "HAS_VOTED|" + pub;
                    vector<unsigned char> identity_data(voted_record.begin(), voted_record.end());
                    bc.insert_block(identity_data);

                    // 2. Cast anonymous vote (Data block)
                    string vote_record = "ANONYMOUS_VOTE|" + opt_hash;
                    vector<unsigned char> vote_data(vote_record.begin(), vote_record.end());
                    bc.insert_block(vote_data);

                    cout << ">>> [SUCCESS] Your vote has been securely and anonymously recorded!" << endl;
                    cout << ">>> Identity decoupled from vote to ensure privacy." << endl;
                } else {
                    cout << "Invalid choice." << endl;
                }
            }
        } else if (choice == 2) {
            vector<string> options = bc.get_options();
            cout << "\n--- Candidates ---" << endl;
            for (string s : options) cout << "- " << s << endl;
        } else if (choice == 3) {
            string filename;
            cout << "Enter filename to save as (e.g. key_backup.txt): ";
            cin >> filename;
            ofstream outFile(filename);
            if (outFile.is_open()) {
                outFile << "======================================\n";
                outFile << "          VOTER CREDENTIALS           \n";
                outFile << "======================================\n";
                outFile << "Secret Key:   " << secret << "\n";
                outFile << "Fingerprint:  " << fingerprint << "\n";
                outFile << "Public Addr:  " << pub << "\n";
                outFile << "--------------------------------------\n";
                outFile << "IMPORTANT: Do not share this file!\n";
                outFile.close();
                cout << ">>> [SUCCESS] Details saved to '" << filename << "'!" << endl;
            } else {
                cout << ">>> [ERROR] Could not save to file." << endl;
            }
        } else if (choice == 4) {
            break;
        }
    }
}

int main() {
    Blockchain bc;
    bc.load_blockchain();

    while (true) {
        cout << "\n==============================================" << endl;
        cout << "       BLOCKCHAIN VOTING SYSTEM v1.0" << endl;
        cout << "==============================================" << endl;
        cout << "1. Admin Login" << endl;
        cout << "2. Polling Agent Login" << endl;
        cout << "3. Voter Registration (Create Account)" << endl;
        cout << "4. Voter Login (Vote)" << endl;
        cout << "5. Exit" << endl;
        cout << "Choice: ";
        
        int choice; 
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(10000, '\n');
            cout << "Invalid input. Please enter a number." << endl;
            continue;
        }

        if (choice == 1) admin_panel(bc);
        else if (choice == 2) polling_agent_panel(bc);
        else if (choice == 3) user_registration(bc);
        else if (choice == 4) user_login(bc);
        else if (choice == 5) break;
        else cout << "Invalid choice." << endl;
    }

    return 0;
}




// BD001 1234
// BD002 5678
// BD003 9012
// BD004 3456
// BD005 7890
// BD006 1357
// BD007 2468
// BD008 9753
// BD009 8642
// BD010 1122




//.\voting.exe