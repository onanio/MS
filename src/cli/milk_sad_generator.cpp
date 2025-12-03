#include <iostream>
#include <fstream>
#include <random>
#include <vector>
#include <string>
#include <iomanip>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sstream>
#include <ctime>
#include <cmath>
#include <stdexcept>
#include <algorithm>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <cctype>
#include <tuple>

// --- HEADER BARU UNTUK MULTIPROCESSING ---
#include <thread>         // Untuk std::thread::hardware_concurrency
#include <sys/wait.h>     // Untuk waitpid
#include <atomic>         // Untuk g_interrupted
// --- AKHIR HEADER BARU ---

// Configuration
const std::string WORDLIST_DIR = "./Wordlist/";
const std::string OUTPUT_FILE_SINGLE_PREFIX = "address_private_key_";
const std::string OUTPUT_FILE_RANGE_PREFIX = "addresses_private_keys_range_";
const std::string OUTPUT_FILE_FULL_PREFIX = "all_addresses_private_keys_";
const std::string PROGRESS_FILE_RANGE = "generation_progress_range.bin";
const std::string PROGRESS_FILE_FULL = "generation_progress_full.bin";
const size_t MNEMONIC_WORD_COUNT = 24;
const uint64_t REPORT_INTERVAL = 10000000ULL; // Sekarang per-proses

// Available wordlists
const std::vector<std::string> WORDLIST_FILES = {
    "english.txt",
    "spanish.txt",
    "french.txt",
    "italian.txt",
    "portuguese.txt",
    "japanese.txt",
    "korean.txt",
    "chinese_simplified.txt",
    "chinese_traditional.txt",
    "russian.txt",
    "ukrainian.txt",
    "czech.txt"
};

// Bech32 constants
const std::string BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const uint32_t BECH32_GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

// --- VARIABEL GLOBAL UNTUK PENANGANAN SINYAL ---
std::vector<pid_t> g_child_pids;
std::atomic<bool> g_interrupted(false);
// --- AKHIR VARIABEL GLOBAL ---

// --- AWAL FUNGSI BIP32/BIP44 BARU ---

// Struktur untuk menyimpan HD Key (Private Key + Chain Code)
struct HDKey {
    std::vector<uint8_t> key;
    std::vector<uint8_t> chain_code;
};

// Helper untuk konversi uint32_t ke 4-byte Big Endian
std::vector<uint8_t> uint32_to_be_bytes(uint32_t val) {
    std::vector<uint8_t> bytes(4);
    bytes[0] = (val >> 24) & 0xFF;
    bytes[1] = (val >> 16) & 0xFF;
    bytes[2] = (val >> 8) & 0xFF;
    bytes[3] = val & 0xFF;
    return bytes;
}
// --- AKHIR FUNGSI BIP32/BIP44 BARU ---


// Helper functions
std::string remove_whitespace(const std::string& str) {
    std::string result = str;
    result.erase(std::remove_if(result.begin(), result.end(), ::isspace), result.end());
    return result;
}

std::string get_filename_base(const std::string& wordlist) {
    size_t dot_pos = wordlist.find('.');
    return (dot_pos != std::string::npos) ? wordlist.substr(0, dot_pos) : wordlist;
}

bool file_exists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

std::vector<std::string> load_wordlist(const std::string& filename) {
    std::vector<std::string> wordlist;
    std::ifstream file(WORDLIST_DIR + filename);

    if (!file) {
        std::cerr << "Error: Could not open wordlist file at " << WORDLIST_DIR + filename << std::endl;
        exit(1);
    }

    std::string word;
    while (std::getline(file, word)) {
        word.erase(word.find_last_not_of(" \t\r\n") + 1);
        if (!word.empty()) {
            wordlist.push_back(word);
        }
    }

    if (wordlist.size() != 2048) {
        std::cerr << "Error: Wordlist must contain exactly 2048 words (found " << wordlist.size() << ")" << std::endl;
        exit(1);
    }

    return wordlist;
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data.data(), data.size());
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256_Final(hash.data(), &sha256_ctx);
    return hash;
}

// BIP39 seed generation - Libbitcoin compatible
std::vector<uint8_t> mnemonic_to_seed(const std::string& mnemonic, const std::string& passphrase = "") {
    std::string salt = "mnemonic" + passphrase;
    std::vector<uint8_t> seed(64);
    
    PKCS5_PBKDF2_HMAC(
        mnemonic.c_str(), mnemonic.length(),
        reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
        2048, EVP_sha512(), 64, seed.data()
    );
    
    return seed;
}

// Generate compressed public key from private key
std::vector<uint8_t> private_key_to_public_key(const std::vector<uint8_t>& private_key, bool compressed = true) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    
    // Set private key
    BIGNUM* priv_bn = BN_bin2bn(private_key.data(), 32, NULL);
    EC_KEY_set_private_key(ec_key, priv_bn);
    
    // Generate public key
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* pub_point = EC_POINT_new(group);
    EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL);
    
    // Convert to public key format
    size_t pub_len = compressed ? 33 : 65;
    std::vector<uint8_t> public_key(pub_len);
    EC_POINT_point2oct(group, pub_point, 
                       compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
                       public_key.data(), pub_len, NULL);
    
    EC_POINT_free(pub_point);
    BN_free(priv_bn);
    EC_KEY_free(ec_key);
    
    return public_key;
}

// --- FUNGSI BIP32 BARU ---

// HD (BIP32) Master Key generation from seed
HDKey hd_master_key_from_seed(const std::vector<uint8_t>& seed) {
    const std::string hd_key = "Bitcoin seed";
    std::vector<uint8_t> hmac_result(64);
    
    HMAC(EVP_sha512(), hd_key.c_str(), hd_key.length(),
         seed.data(), seed.size(), hmac_result.data(), NULL);
    
    HDKey master_key;
    master_key.key.assign(hmac_result.begin(), hmac_result.begin() + 32);
    master_key.chain_code.assign(hmac_result.begin() + 32, hmac_result.end());
    
    // Ensure private key is valid (within curve order)
    BIGNUM* bn = BN_bin2bn(master_key.key.data(), 32, NULL);
    BIGNUM* curve_order = BN_new();
    BN_hex2bn(&curve_order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    
    if (BN_cmp(bn, curve_order) >= 0 || BN_is_zero(bn)) {
        // Ini seharusnya tidak terjadi untuk seed yang valid, tapi sebagai pengaman
        BN_free(bn);
        BN_free(curve_order);
        throw std::runtime_error("Invalid master key generated (>= curve order or zero)");
    }
    
    BN_free(bn);
    BN_free(curve_order);
    
    return master_key;
}

// BIP32 Private Parent Key -> Private Child Key derivation
HDKey CKDpriv(const HDKey& parent_key, uint32_t index) {
    std::vector<uint8_t> hmac_data;
    bool hardened = (index & 0x80000000);
    
    if (hardened) {
        // Hardened derivation: 0x00 || parent_key (32) || index (4)
        hmac_data.push_back(0x00);
        hmac_data.insert(hmac_data.end(), parent_key.key.begin(), parent_key.key.end());
    } else {
        // Normal derivation: parent_public_key (33) || index (4)
        std::vector<uint8_t> pub_key = private_key_to_public_key(parent_key.key, true); // Kompresi
        hmac_data.insert(hmac_data.end(), pub_key.begin(), pub_key.end());
    }
    
    // Tambahkan index (Big Endian)
    std::vector<uint8_t> index_bytes = uint32_to_be_bytes(index);
    hmac_data.insert(hmac_data.end(), index_bytes.begin(), index_bytes.end());
    
    // HMAC-SHA512(Key = parent_chain_code, Data = hmac_data)
    std::vector<uint8_t> hmac_result(64);
    HMAC(EVP_sha512(), parent_key.chain_code.data(), parent_key.chain_code.size(),
         hmac_data.data(), hmac_data.size(), hmac_result.data(), NULL);
         
    std::vector<uint8_t> I_L(hmac_result.begin(), hmac_result.begin() + 32);
    std::vector<uint8_t> I_R(hmac_result.begin() + 32, hmac_result.end()); // Child chain code
    
    // Hitung child key: (I_L + parent_key) % n
    BIGNUM* bn_I_L = BN_bin2bn(I_L.data(), 32, NULL);
    BIGNUM* bn_parent_key = BN_bin2bn(parent_key.key.data(), 32, NULL);
    BIGNUM* curve_order = BN_new();
    BIGNUM* bn_child_key = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    
    BN_hex2bn(&curve_order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    
    // Cek 1: I_L >= n
    if (BN_cmp(bn_I_L, curve_order) >= 0) {
        BN_free(bn_I_L); BN_free(bn_parent_key); BN_free(curve_order); BN_free(bn_child_key); BN_CTX_free(ctx);
        throw std::runtime_error("Invalid derived key: I_L >= n");
    }
    
    // (I_L + parent_key) % n
    BN_mod_add(bn_child_key, bn_I_L, bn_parent_key, curve_order, ctx);
    
    // Cek 2: child_key == 0
    if (BN_is_zero(bn_child_key)) {
        BN_free(bn_I_L); BN_free(bn_parent_key); BN_free(curve_order); BN_free(bn_child_key); BN_CTX_free(ctx);
        throw std::runtime_error("Invalid derived key: k_i == 0");
    }
    
    std::vector<uint8_t> child_key_bytes(32);
    BN_bn2binpad(bn_child_key, child_key_bytes.data(), 32);
    
    BN_free(bn_I_L);
    BN_free(bn_parent_key);
    BN_free(curve_order);
    BN_free(bn_child_key);
    BN_CTX_free(ctx);
    
    return HDKey{child_key_bytes, I_R};
}

// Melakukan derivasi key dari path string (e.g., "m/44'/0'/0'/0/0")
HDKey derive_key_from_path(const HDKey& master_key, const std::string& path) {
    if (path.empty() || path[0] != 'm') {
        throw std::runtime_error("Invalid derivation path: must start with 'm'");
    }
    
    HDKey current_key = master_key;
    std::stringstream ss(path);
    std::string component;
    
    std::getline(ss, component, '/'); // Skip 'm'
    
    while (std::getline(ss, component, '/')) {
        if (component.empty()) continue;
        
        bool hardened = false;
        if (component.back() == '\'') {
            hardened = true;
            component.pop_back();
        }
        
        uint32_t index;
        try {
            index = std::stoul(component);
        } catch (const std::exception& e) {
            throw std::runtime_error("Invalid path component: " + component);
        }
        
        if (hardened) {
            index |= 0x80000000;
        }
        
        current_key = CKDpriv(current_key, index);
    }
    
    return current_key;
}

// --- AKHIR FUNGSI BIP32 BARU ---


// Generate Legacy Bitcoin address (P2PKH) - Dibiarkan, tapi tidak digunakan
std::string private_key_to_legacy_address(const std::vector<uint8_t>& private_key) {
    std::vector<uint8_t> public_key = private_key_to_public_key(private_key, true);
    
    // SHA-256 hash of public key
    std::vector<uint8_t> sha256_hash = sha256(public_key);
    
    // RIPEMD-160 hash of SHA-256
    std::vector<uint8_t> ripemd_hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160(sha256_hash.data(), sha256_hash.size(), ripemd_hash.data());
    
    // Add version byte (0x00 for Bitcoin mainnet)
    std::vector<uint8_t> extended_hash(1 + ripemd_hash.size());
    extended_hash[0] = 0x00;
    std::copy(ripemd_hash.begin(), ripemd_hash.end(), extended_hash.begin() + 1);
    
    // Double SHA-256 for checksum
    std::vector<uint8_t> checksum = sha256(sha256(extended_hash));
    
    // Append first 4 bytes of checksum
    std::vector<uint8_t> binary_address(extended_hash.size() + 4);
    std::copy(extended_hash.begin(), extended_hash.end(), binary_address.begin());
    std::copy(checksum.begin(), checksum.begin() + 4, binary_address.begin() + extended_hash.size());
    
    // Base58 encoding
    const std::string base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string address;
    
    // Convert to base58
    BIGNUM* bn_addr = BN_bin2bn(binary_address.data(), binary_address.size(), NULL);
    
    while (BN_is_zero(bn_addr) == 0) {
        BN_ULONG remainder = BN_div_word(bn_addr, 58);
        address = base58_chars[remainder] + address;
    }
    
    // Add '1' for each leading zero byte
    for (size_t i = 0; i < binary_address.size() && binary_address[i] == 0; i++) {
        address = '1' + address;
    }
    
    BN_free(bn_addr);
    return address;
}

// Generate Nested SegWit address (P2SH-P2WPKH)
std::string private_key_to_nested_segwit_address(const std::vector<uint8_t>& private_key) {
    std::vector<uint8_t> public_key = private_key_to_public_key(private_key, true);
    std::vector<uint8_t> sha256_hash = sha256(public_key);
    std::vector<uint8_t> pubkey_hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160(sha256_hash.data(), sha256_hash.size(), pubkey_hash.data());
    
    // Redeam Script (P2WPKH script): 0x00 (OP_0) + 0x14 (OP_PUSHBYTES_20) + HASH160(Compressed Public Key)
    std::vector<uint8_t> redeem_script(22);
    redeem_script[0] = 0x00; // Witness version (OP_0)
    redeem_script[1] = 0x14; // Push 20 bytes
    std::copy(pubkey_hash.begin(), pubkey_hash.end(), redeem_script.begin() + 2);
    
    // Hash the Redeem Script (SHA256 then RIPEMD160) for P2SH
    std::vector<uint8_t> sha256_redeem_script = sha256(redeem_script);
    std::vector<uint8_t> script_hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160(sha256_redeem_script.data(), sha256_redeem_script.size(), script_hash.data());
    
    // Add version byte (0x05 for P2SH mainnet)
    std::vector<uint8_t> extended_hash(1 + script_hash.size());
    extended_hash[0] = 0x05; // P2SH version byte
    std::copy(script_hash.begin(), script_hash.end(), extended_hash.begin() + 1);
    
    // Double SHA-256 for checksum
    std::vector<uint8_t> checksum = sha256(sha256(extended_hash));
    
    std::vector<uint8_t> binary_address(extended_hash.size() + 4);
    std::copy(extended_hash.begin(), extended_hash.end(), binary_address.begin());
    std::copy(checksum.begin(), checksum.begin() + 4, binary_address.begin() + extended_hash.size());
    
    // Base58 encoding
    const std::string base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string address;
    
    BIGNUM* bn_addr = BN_bin2bn(binary_address.data(), binary_address.size(), NULL);
    
    while (BN_is_zero(bn_addr) == 0) {
        BN_ULONG remainder = BN_div_word(bn_addr, 58);
        address = base58_chars[remainder] + address;
    }
    
    for (size_t i = 0; i < binary_address.size() && binary_address[i] == 0; i++) {
        address = '1' + address;
    }
    
    BN_free(bn_addr);
    return address;
}

// Bech32 encoding functions - Dibiarkan, tapi tidak digunakan
uint32_t bech32_polymod(const std::vector<uint8_t>& values) {
    uint32_t chk = 1;
    for (uint8_t value : values) {
        uint8_t top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ value;
        for (int i = 0; i < 5; ++i) {
            if ((top >> i) & 1) {
                chk ^= BECH32_GEN[i];
            }
        }
    }
    return chk;
}

std::vector<uint8_t> bech32_hrp_expand(const std::string& hrp) {
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size() * 2 + 1);
    for (char c : hrp) {
        ret.push_back(static_cast<uint8_t>(c) >> 5);
    }
    ret.push_back(0);
    for (char c : hrp) {
        ret.push_back(static_cast<uint8_t>(c) & 0x1f);
    }
    return ret;
}

std::string bech32_encode(const std::string& hrp, const std::vector<uint8_t>& values) {
    std::vector<uint8_t> combined = bech32_hrp_expand(hrp);
    combined.insert(combined.end(), values.begin(), values.end());
    
    combined.resize(combined.size() + 6);
    
    uint32_t polymod = bech32_polymod(combined) ^ 1;
    std::vector<uint8_t> checksum(6);
    for (int i = 0; i < 6; ++i) {
        checksum[i] = (polymod >> (5 * (5 - i))) & 0x1f;
    }
    
    std::string ret = hrp + "1";
    for (uint8_t value : values) {
        ret += BECH32_CHARS[value];
    }
    for (uint8_t value : checksum) {
        ret += BECH32_CHARS[value];
    }
    return ret;
}

std::vector<uint8_t> convert_bits(const std::vector<uint8_t>& data, int frombits, int tobits, bool pad = true) {
    int acc = 0;
    int bits = 0;
    std::vector<uint8_t> ret;
    int maxv = (1 << tobits) - 1;
    int max_acc = (1 << (frombits + tobits - 1)) - 1;
    
    for (uint8_t value : data) {
        if (value < 0 || (value >> frombits)) {
            return {};
        }
        acc = ((acc << frombits) | value) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            ret.push_back((acc >> bits) & maxv);
        }
    }
    
    if (pad) {
        if (bits) {
            ret.push_back((acc << (tobits - bits)) & maxv);
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return {};
    }
    
    return ret;
}

// Generate Native SegWit address (Bech32/P2WPKH) - Dibiarkan, tapi tidak digunakan
std::string private_key_to_native_segwit_address(const std::vector<uint8_t>& private_key) {
    std::vector<uint8_t> public_key = private_key_to_public_key(private_key, true);
    std::vector<uint8_t> sha256_hash = sha256(public_key);
    std::vector<uint8_t> pubkey_hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160(sha256_hash.data(), sha256_hash.size(), pubkey_hash.data());
    
    std::vector<uint8_t> converted_data = convert_bits(pubkey_hash, 8, 5, true);
    std::vector<uint8_t> bech32_data;
    bech32_data.push_back(0x00); // Witness version 0
    bech32_data.insert(bech32_data.end(), converted_data.begin(), converted_data.end());
    
    return bech32_encode("bc", bech32_data);
}

// Convert bytes to hex string
std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// WIF format private key
std::string private_key_to_wif(const std::vector<uint8_t>& private_key, bool use_compressed = true) {
    std::vector<uint8_t> extended_key(1 + private_key.size());
    extended_key[0] = 0x80;
    std::copy(private_key.begin(), private_key.end(), extended_key.begin() + 1);
    
    if (use_compressed) {
        extended_key.push_back(0x01);
    }
    
    std::vector<uint8_t> checksum = sha256(sha256(extended_key));
    
    std::vector<uint8_t> wif_bytes(extended_key.size() + 4);
    std::copy(extended_key.begin(), extended_key.end(), wif_bytes.begin());
    std::copy(checksum.begin(), checksum.begin() + 4, wif_bytes.begin() + extended_key.size());
    
    const std::string base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string wif;
    
    BIGNUM* bn_wif = BN_bin2bn(wif_bytes.data(), wif_bytes.size(), NULL);
    
    while (BN_is_zero(bn_wif) == 0) {
        BN_ULONG remainder = BN_div_word(bn_wif, 58);
        wif = base58_chars[remainder] + wif;
    }
    
    for (size_t i = 0; i < wif_bytes.size() && wif_bytes[i] == 0; i++) {
        wif = '1' + wif;
    }
    
    BN_free(bn_wif);
    return wif;
}

std::string generate_mnemonic_bip39(uint32_t seed_value, const std::vector<std::string>& wordlist) {
    std::mt19937 engine(seed_value);
    std::vector<uint8_t> entropy(32);
    std::uniform_int_distribution<uint16_t> distribution(0, std::numeric_limits<uint8_t>::max());

    for (size_t i = 0; i < 32; ++i) {
        entropy[i] = static_cast<uint8_t>(distribution(engine));
    }

    std::vector<uint8_t> hash = sha256(entropy);
    const size_t CHECKSUM_LENGTH_BITS = entropy.size() * 8 / 32;
    std::vector<uint8_t> combined_data = entropy;
    combined_data.insert(combined_data.end(), hash.begin(), hash.begin() + (CHECKSUM_LENGTH_BITS + 7) / 8);

    std::string mnemonic;
    size_t combined_data_bit_index = 0;
    for (size_t i = 0; i < MNEMONIC_WORD_COUNT; ++i) {
        uint16_t word_index = 0;
        for (int bit = 10; bit >= 0; --bit) {
            size_t byte_index = combined_data_bit_index / 8;
            int bit_in_byte = 7 - (combined_data_bit_index % 8);

            if (byte_index < combined_data.size()) {
                if ((combined_data[byte_index] >> bit_in_byte) & 1) {
                    word_index |= (1 << bit);
                }
                combined_data_bit_index++;
            }
        }
        if (!mnemonic.empty()) mnemonic += " ";
        mnemonic += wordlist[word_index];
    }
    return mnemonic;
}

// --- FUNGSI DIPERBARUI UNTUK HANYA MENGHASILKAN ALAMAT BIP49 ---
// Mengembalikan vector dari tuple: (nested, wif, path)
// Catatan: Legacy dan Native dihapus dari tuple dan proses
std::vector<std::tuple<std::string, std::string, std::string>> 
generate_all_addresses_and_private_key(const std::string& mnemonic, int num_addresses) {
    
    // PERUBAHAN UTAMA: Path BIP49 (Nested SegWit)
    // m/49' / 0' / 0' / 0 / i (Change/Index)
    const std::string base_derivation_path = "m/49'/0'/0'/0/"; 

    // Tuple sekarang hanya berisi (Nested SegWit Address, Private Key WIF, Path)
    std::vector<std::tuple<std::string, std::string, std::string>> results;
    results.reserve(num_addresses);

    // 1. Mnemonic -> Seed
    std::vector<uint8_t> seed = mnemonic_to_seed(mnemonic);
    
    // 2. Seed -> Master Key (BIP32)
    HDKey master_key = hd_master_key_from_seed(seed);
    
    // Loop untuk menghasilkan jumlah alamat yang diminta
    for (int i = 0; i < num_addresses; ++i) {
        std::string current_path = base_derivation_path + std::to_string(i);
        
        try {
            // 3. Master Key -> Derived Child Key (sesuai path)
            HDKey derived_key = derive_key_from_path(master_key, current_path);
            
            // 4. Gunakan 'derived_key.key' sebagai private key final
            std::vector<uint8_t> private_key = derived_key.key;
            
            // 5. Hasilkan HANYA alamat Nested SegWit dan WIF
            std::string nested_segwit_address = private_key_to_nested_segwit_address(private_key);
            std::string private_key_wif = private_key_to_wif(private_key, true); // BIP49 menggunakan compressed key
            
            // Tambahkan ke vector hasil: (Nested SegWit, WIF, Path)
            results.emplace_back(nested_segwit_address, private_key_wif, current_path);
        
        } catch (const std::exception& e) {
            // Jika 1 derivasi gagal (jarang), catat dan lanjut ke indeks berikutnya
            std::cerr << "Warning: Derivation failed for path " << current_path 
                      << " (mnemonic: " << mnemonic.substr(0, 10) << "...): " << e.what() << std::endl;
        }
    }
    
    return results;
}

void save_progress(const std::string& progress_file, uint32_t last_timestamp) {
    std::ofstream out(progress_file, std::ios::binary);
    if (out.is_open()) {
        out.write(reinterpret_cast<const char*>(&last_timestamp), sizeof(last_timestamp));
    }
    else {
        std::cerr << "Error: Could not write to progress file " << progress_file << std::endl;
    }
}

uint32_t load_progress(const std::string& progress_file) {
    if (!file_exists(progress_file)) return 0;
    std::ifstream in(progress_file, std::ios::binary);
    uint32_t last_timestamp;
    if (in.is_open()) {
        in.read(reinterpret_cast<char*>(&last_timestamp), sizeof(last_timestamp));
        if (!in.good()) {
            return 0;
        }
    }
    else {
        std::cerr << "Error: Could not read from progress file " << progress_file << std::endl;
        return 0;
    }
    return last_timestamp;
}

// --- SIGNAL HANDLER BARU ---
void signal_handler(int signum) {
    if (g_interrupted) return;
    g_interrupted = true;
    
    std::cerr << "\nInterrupt received (" << signum << "). Terminating child processes..." << std::endl;
    
    // Kirim sinyal ke semua child process
    for (pid_t pid : g_child_pids) {
        if (pid > 0) {
            kill(pid, SIGTERM);
        }
    }
    // Parent akan keluar setelah loop waitpid() mendeteksi child selesai
}

std::tm parse_datetime(const std::string& datetime_str) {
    std::tm tm = {};
    std::stringstream ss(datetime_str);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    if (ss.fail()) {
        throw std::runtime_error("Invalid date/time format. Use YYYY-MM-DD HH:MM:SS");
    }
    return tm;
}

void parse_date_range(const std::string& range_str, std::tm& start_tm, std::tm& end_tm) {
    std::string clean_str = remove_whitespace(range_str);
    size_t colon_pos = clean_str.find(':');
    if (colon_pos == std::string::npos) {
        throw std::runtime_error("Invalid format. Use YYYY-MM-DD:YYYY-MM-DD");
    }

    std::string start_str = clean_str.substr(0, colon_pos);
    std::string end_str = clean_str.substr(colon_pos + 1);

    std::stringstream ss_start(start_str);
    ss_start >> std::get_time(&start_tm, "%Y-%m-%d");
    if (ss_start.fail()) {
        throw std::runtime_error("Invalid start date format.");
    }

    std::stringstream ss_end(end_str);
    ss_end >> std::get_time(&end_tm, "%Y-%m-%d");
    if (ss_end.fail()) {
        throw std::runtime_error("Invalid end date format.");
    }
}

uint32_t get_unix_timestamp(int year, int month, int day, int hour, int minute, int second) {
    std::tm t{};
    t.tm_year = year - 1900;
    t.tm_mon = month - 1;
    t.tm_mday = day;
    t.tm_hour = hour;
    t.tm_min = minute;
    t.tm_sec = second;
    t.tm_isdst = 0;

    #ifdef _WIN32
        _putenv("TZ=UTC");
        _tzset();
    #else
        setenv("TZ", "UTC", 1);
        tzset();
    #endif

    std::time_t timestamp = std::mktime(&t);
    if (timestamp == -1) {
        throw std::runtime_error("Invalid date/time for timestamp conversion");
    }
    return static_cast<uint32_t>(timestamp);
}

int select_wordlist() {
    std::cout << "Available wordlists:\n";
    for (size_t i = 0; i < WORDLIST_FILES.size(); ++i) {
        std::cout << i + 1 << ". " << WORDLIST_FILES[i] << "\n";
    }
    std::cout << "Select wordlist (1-" << WORDLIST_FILES.size() << "): ";
    
    int choice;
    while (true) {
        std::cin >> choice;
        if (std::cin.fail() || choice < 1 || choice > static_cast<int>(WORDLIST_FILES.size())) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid choice. Please enter a number between 1 and " << WORDLIST_FILES.size() << ": ";
        } else {
            break;
        }
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return choice - 1;
}

// --- FUNGSI HELPER BARU ---
int get_num_processes() {
    unsigned int max_cores = std::thread::hardware_concurrency();
    if (max_cores == 0) max_cores = 2; // Default jika tidak terdeteksi
    
    std::cout << "Enter number of processes to use (Recommended: " << max_cores << "): ";
    int num_proc;
    std::cin >> num_proc;
    if (std::cin.fail() || num_proc < 1) {
        std::cout << "Invalid input. Using " << max_cores << " processes." << std::endl;
        num_proc = max_cores;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return num_proc;
}

// --- FUNGSI HELPER BARU (DARI UPGRADE) ---
int get_num_addresses_per_mnemonic() {
    std::cout << "Enter number of addresses to generate per mnemonic (e.g., 1, 5, 10): ";
    int num_addr;
    std::cin >> num_addr;
    if (std::cin.fail() || num_addr < 1) {
        std::cout << "Invalid input. Using 1 address." << std::endl;
        num_addr = 1;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return num_addr;
}


// --- FUNGSI GENERASI PARALEL (DIPERBARUI) ---
void run_parallel_generation(
    uint32_t start_timestamp, 
    uint32_t end_timestamp, 
    const std::string& base_output_file, 
    const std::string& base_progress_file, 
    const std::vector<std::string>& wordlist,
    int num_addresses 
) {
    int num_processes = get_num_processes();
    std::cout << "Starting " << num_processes << " worker processes..." << std::endl;
    g_child_pids.resize(num_processes, 0);

    for (int i = 0; i < num_processes; ++i) {
        pid_t pid = fork();

        if (pid == -1) {
            std::cerr << "Error: fork() failed." << std::endl;
            // Kirim sinyal ke child yang sudah terlanjur dibuat
            for (pid_t child_pid : g_child_pids) {
                if (child_pid > 0) kill(child_pid, SIGTERM);
            }
            return;
        } else if (pid == 0) {
            // --- INI ADALAH PROSES CHILD ---
            
            // Child tidak perlu menangani sinyal, biarkan parent
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);

            std::string child_output_file = base_output_file + ".part" + std::to_string(i);
            std::string child_progress_file = base_progress_file + ".part" + std::to_string(i);
            
            std::ofstream outfile_child(child_output_file, std::ios::app);
            if (!outfile_child) {
                std::cerr << "Child " << i << " failed to open output file " << child_output_file << "!" << std::endl;
                exit(1); 
            }

            uint32_t current_timestamp = load_progress(child_progress_file);
            uint32_t child_start_ts;

            if (current_timestamp == 0 || current_timestamp < start_timestamp) {
                child_start_ts = start_timestamp;
            } else {
                child_start_ts = current_timestamp;
            }

            // Sejajarkan (align) ke starting point yang benar untuk child ini
            if (child_start_ts <= end_timestamp) {
                uint32_t offset = (child_start_ts - start_timestamp) % num_processes;
                if (offset != i) {
                    uint32_t adjustment = (i - offset + num_processes) % num_processes;
                    if (child_start_ts > std::numeric_limits<uint32_t>::max() - adjustment) {
                        child_start_ts = end_timestamp + 1; 
                    } else {
                        child_start_ts += adjustment;
                    }
                }
            }

            // Pastikan tidak mulai sebelum start_timestamp + i
            if (child_start_ts < start_timestamp + i && (start_timestamp + i) > start_timestamp) {
                child_start_ts = start_timestamp + i;
            }


            std::cout << "Process " << i << " starting from timestamp " << child_start_ts << std::endl;
            uint64_t report_counter = 0;

            for (uint32_t ts = child_start_ts; ts <= end_timestamp; ts += num_processes) {
                if (g_interrupted.load()) break; // Cek interupsi di Child
                
                try {
                    std::string mnemonic = generate_mnemonic_bip39(ts, wordlist);
                    
                    // Panggil fungsi yang diperbarui (Hanya BIP49)
                    auto address_list = generate_all_addresses_and_private_key(mnemonic, num_addresses);
                    
                    // Format: [nested_segwit_address] [wif] [path]
                    for (const auto& addresses : address_list) {
                        outfile_child << std::get<0>(addresses) << " " // nested
                                      << std::get<1>(addresses) << " " // wif
                                      << std::get<2>(addresses) << "\n"; // path
                    }

                } catch (const std::exception& e) {
                    std::cerr << "Process " << i << " skipped timestamp " << ts << " due to critical error: " << e.what() << std::endl;
                }
                
                report_counter++;

                if (report_counter % 100000 == 0) {
                    if (ts > std::numeric_limits<uint32_t>::max() - num_processes) {
                        save_progress(child_progress_file, end_timestamp + 1); // Mark done
                    } else {
                        save_progress(child_progress_file, ts + num_processes);
                    }
                }

                if (ts > end_timestamp - num_processes) {
                    // Mencegah overflow pada ts += num_processes
                    break; 
                }
            }
            
            if (g_interrupted.load()) {
                // Jika diinterupsi, simpan progress saat ini
                if (ts <= end_timestamp) {
                    save_progress(child_progress_file, ts); 
                }
                outfile_child.close();
                exit(1); // Exit dengan status error
            }

            // Simpan progress terakhir sebagai tanda selesai
            save_progress(child_progress_file, end_timestamp + 1);
            outfile_child.close();
            std::cout << "Process " << i << " finished." << std::endl;
            exit(0); // --- PENTING: Child harus keluar dengan status sukses ---
        } else {
            // --- INI ADALAH PROSES PARENT ---
            g_child_pids[i] = pid;
        }
    }

    // --- PARENT PROCESS ---
    // Tunggu semua child selesai
    int status;
    bool all_ok = true;
    for (int i = 0; i < num_processes; ++i) {
        pid_t pid = g_child_pids[i];
        if (pid > 0) {
            waitpid(pid, &status, 0);
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                std::cerr << "Child process " << pid << " (index " << i << ") exited with error or was terminated." << std::endl;
                all_ok = false;
            }
        } else {
            all_ok = false; 
        }
    }

    if (g_interrupted) {
        std::cerr << "Process interrupted by user. Part files are kept for resume." << std::endl;
        return;
    }

    if (!all_ok) {
         std::cerr << "One or more child processes failed. Output files may be incomplete. Part files will be kept for inspection." << std::endl;
         return;
    }

    std::cout << "All child processes finished. Concatenating output files..." << std::endl;
    
    // Gabungkan file
    std::ofstream final_outfile(base_output_file); // Mode timpa (truncate)
    if (!final_outfile) {
         std::cerr << "Failed to open final output file " << base_output_file << "!" << std::endl;
         return;
    }

    for (int i = 0; i < num_processes; ++i) {
        std::string child_output_file = base_output_file + ".part" + std::to_string(i);
        std::string child_progress_file = base_progress_file + ".part" + std::to_string(i);

        std::ifstream infile_child(child_output_file);
        if (infile_child) {
            final_outfile << infile_child.rdbuf();
            infile_child.close();
            unlink(child_output_file.c_str());
        } else {
            std::cerr << "Warning: Could not open part file " << child_output_file << std::endl;
        }
        
        unlink(child_progress_file.c_str()); 
    }

    final_outfile.close();
    std::cout << "Generation complete. All BIP49 addresses and private keys saved to " << base_output_file << "\n";
}

// --- MAIN FUNCTION (DIPERBARUI) ---
int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::cout << "Milk Sad Address and Private Key Generator (Libbitcoin Compatible)" << std::endl;
    std::cout << "--- BIP49 (Nested SegWit) ONLY ---" << std::endl; // Info upgrade
    std::cout << "--- NOW WITH MULTIPROCESSING ---" << std::endl;
    std::cout << "--- NOW WITH MULTIPLE ADDRESSES PER MNEMONIC ---" << std::endl; 
    std::cout << "------------------------" << std::endl;
    std::cout << "Now only generating Nested SegWit (3...) addresses." << std::endl;
    std::cout << "Developed by z1ph1us" << std::endl;
    std::cout << "------------------------" << std::endl;
    
    int wordlist_choice = select_wordlist();
    std::string wordlist_name = WORDLIST_FILES[wordlist_choice];
    std::string wordlist_base = get_filename_base(wordlist_name);
    std::cout << "Loading " << wordlist_name << " wordlist..." << std::endl;
    auto wordlist = load_wordlist(wordlist_name);

    std::cout << "Options:\n";
    std::cout << "1. Generate address and private key for a specific date/time. (Mostly for testing purposes)\n";
    std::cout << "2. Generate addresses and private keys for a date range. (Multiprocess)\n";
    std::cout << "3. Generate addresses and private keys for the full Unix timestamp range (Multiprocess).\n";
    std::cout << "Type your choice (1, 2, or 3) and press Enter: ";

    int choice;
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    if (choice < 1 || choice > 3) {
        std::cerr << "Error: Invalid choice." << std::endl;
        return 1;
    }

    int num_addresses = get_num_addresses_per_mnemonic();


    if (choice == 1) {
        // --- PILIHAN 1 (SINGLE) - DIPERBARUI ---
        std::string datetime_str;
        std::cout << "Enter the date/time (YYYY-MM-DD HH:MM:SS)(Use 1970-01-01 00:00:00 for 0 value): ";
        std::getline(std::cin, datetime_str);

        std::tm tm;
        try {
            tm = parse_datetime(datetime_str);
        } catch (const std::runtime_error& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
        
        uint32_t timestamp = get_unix_timestamp(
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec
        );
        
        std::string output_file = OUTPUT_FILE_SINGLE_PREFIX + wordlist_base + "_bip49" + ".txt";
        std::ofstream outfile(output_file);
        if (outfile.is_open()) {
            std::string mnemonic = generate_mnemonic_bip39(timestamp, wordlist);
            std::cout << "Generating for mnemonic: " << mnemonic << std::endl;
            
            try {
                // Panggil fungsi yang diperbarui
                auto address_list = generate_all_addresses_and_private_key(mnemonic, num_addresses);
                
                std::cout << "Addresses for " << datetime_str << " (timestamp " << timestamp << "):" << std::endl;
                outfile << "Mnemonic: " << mnemonic << std::endl;
                outfile << "Timestamp: " << timestamp << std::endl;
                outfile << "------------------------" << std::endl;
                
                // Loop melalui hasil (Hanya Nested SegWit)
                for (const auto& addresses : address_list) {
                    std::string nested_segwit_address = std::get<0>(addresses);
                    std::string private_key = std::get<1>(addresses);
                    std::string path = std::get<2>(addresses);

                    outfile << "Path: " << path << std::endl;
                    outfile << "  Nested SegWit Address (BIP49/P2SH-P2WPKH): " << nested_segwit_address << std::endl;
                    outfile << "  Private Key (WIF): " << private_key << std::endl;
                    outfile << "---" << std::endl;

                    std::cout << "Path: " << path << std::endl;
                    std::cout << "  Nested SegWit Address (BIP49/P2SH-P2WPKH): " << nested_segwit_address << std::endl;
                    std::cout << "  Private Key (WIF): " << private_key << std::endl;
                }

                outfile.close();
                std::cout << "------------------------" << std::endl;
                std::cout << "Saved to " << output_file << std::endl;

            } catch (const std::exception& e) {
                 std::cerr << "Error generating address: " << e.what() << std::endl;
                 outfile.close();
                 return 1;
            }
        }
        else {
            std::cerr << "Error opening output file " << output_file << std::endl;
            return 1;
        }
    }
    else if (choice == 2) {
        // --- PILIHAN 2 (RANGE) - DIPERBARUI ---
        std::string date_range_str;
        std::cout << "Enter the date range in format YYYY-MM-DD:YYYY-MM-DD (Start:End): ";
        std::getline(std::cin, date_range_str);

        std::tm start_tm = {}, end_tm = {};
        try {
            parse_date_range(date_range_str, start_tm, end_tm);
        } catch (const std::runtime_error& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }

        uint32_t start_timestamp = get_unix_timestamp(
            start_tm.tm_year + 1900, start_tm.tm_mon + 1, start_tm.tm_mday, 0, 0, 0);
        uint32_t end_timestamp = get_unix_timestamp(
            end_tm.tm_year + 1900, end_tm.tm_mon + 1, end_tm.tm_mday, 23, 59, 59);

        if (start_timestamp > end_timestamp) {
            std::cerr << "Error: Start date must be before or equal to end date." << std::endl;
            return 1;
        }

        std::string output_file = OUTPUT_FILE_RANGE_PREFIX + wordlist_base + "_bip49" + ".txt";
        std::cout << "Generating BIP49 addresses and private keys for timestamps between "
                  << start_timestamp << " and " << end_timestamp << std::endl;
        std::cout << "Output file: " << output_file << std::endl;

        run_parallel_generation(start_timestamp, end_timestamp, output_file, PROGRESS_FILE_RANGE, wordlist, num_addresses);
    }
    else if (choice == 3) {
        // --- PILIHAN 3 (FULL) - DIPERBARUI ---
        std::string output_file = OUTPUT_FILE_FULL_PREFIX + wordlist_base + "_bip49" + ".txt";
        std::cout << "Generating BIP49 addresses and private keys for the full 32-bit Unix timestamp range." << std::endl;
        std::cout << "Output file: " << output_file << std::endl;
        
        uint32_t start_timestamp = 0;
        uint32_t end_timestamp = std::numeric_limits<uint32_t>::max();

        run_parallel_generation(start_timestamp, end_timestamp, output_file, PROGRESS_FILE_FULL, wordlist, num_addresses);
    }

    return 0;
}
