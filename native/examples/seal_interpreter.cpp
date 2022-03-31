#include "seal_interpreter.h"
#include "argparse.hpp"
#include <cassert>
#include <iostream>

using namespace seal;

int PLAIN = 0;
int ENCRYPTED = 1;

typedef std::variant<Plaintext, Ciphertext> SealText;

enum mode {
    fhe
};

enum op {
    B_AND_,
    B_OR_,
    B_XOR_,
	ADD_,
	SUB_,
	MUL_,
	EQ_,
	GT_,
	LT_,
	GE_,
	LE_,
	REM_,
	AND_,
	OR_,
	XOR_,
	CONS_bv,
	CONS_bool,
	MUX_, 
	NOT_,
	DIV_,
    IN_,
	OUT_,
};

op op_hash(std::string o) {
    if (o == "B_AND") return B_AND_;
    if (o == "B_OR") return B_OR_;
    if (o == "B_XOR") return B_XOR_;
    if (o == "ADD") return ADD_;
	if (o == "SUB") return SUB_;
	if (o == "MUL") return MUL_;
	if (o == "EQ") return EQ_;
	if (o == "GT") return GT_;
	if (o == "LT") return LT_;
	if (o == "GE") return GE_;
	if (o == "LE") return LE_;
	if (o == "REM") return REM_;
	if (o == "AND") return AND_;
	if (o == "OR") return OR_;
	if (o == "XOR") return XOR_;
	if (o == "CONS_bv") return CONS_bv;
	if (o == "CONS_bool") return CONS_bool;
	if (o == "MUX") return MUX_;
	if (o == "NOT") return NOT_;
	if (o == "DIV") return DIV_;
    if (o == "IN") return IN_;
	if (o == "OUT") return OUT_;
    throw std::invalid_argument("Unknown operator: "+o);
}

bool is_bin_op(op o) {
	return o == ADD_ || o == SUB_ || o == MUL_ || o == EQ_ || o == GT_ || o == LT_ || o == GE_ || o == LE_ || o == REM_ || o == DIV_ || o == AND_ || o == OR_ || o == XOR_;
}

bool is_boolnary_op(op o) {
    return o == B_AND_ || o == B_OR_ || o == B_XOR_;
}

std::vector<std::string> split_(std::string str, char delimiter) {
    std::vector<std::string> result;
    std::istringstream ss(str);
    std::string word; 
    while (ss >> word) {
        result.push_back(word);
    }
    return result;
}

SealText get_from_cache(std::unordered_map<std::string, SealText>* cache, std::string key) {	
	std::unordered_map<std::string, SealText>::const_iterator sealtext = cache->find(key);
	if (sealtext == cache->end()){
		throw std::invalid_argument("Unknown wire in cache: " + key);
	}
	else {
		return sealtext->second;
	}
}

SealText process_instruction(
    Encryptor* encryptor,
    Evaluator* evaluator,
    Decryptor* decryptor,
    std::unordered_map<std::string, SealText>* cache,
    std::unordered_map<std::string, uint32_t>* params,
    std::vector<std::string> input_texts, 
    std::string op
) {
    SealText result;
    
    if (is_boolnary_op(op_hash(op))) {
        Ciphertext res;
        SealText s0 = get_from_cache(cache, input_texts[0]);
        if (s0.index() == 0) 
            (*encryptor).encrypt(std::get<Plaintext>(s0), res);
        else
            res = std::get<Ciphertext>(s0);
        
        for (auto it = ++input_texts.begin(); it != input_texts.end(); it++) {
            SealText stext = get_from_cache(cache, *it);
            if (stext.index() == 0) { //If Plaintext
                switch(op_hash(op)) {
                    case B_AND_: {
                        (*evaluator).multiply_plain_inplace(res, std::get<Plaintext>(stext));
                        break;
                    }    
                    case B_OR_: {
                        Ciphertext product;
                        (*evaluator).multiply_plain(res, std::get<Plaintext>(stext), product);
                        (*evaluator).add_plain_inplace(res, std::get<Plaintext>(stext));
                        (*evaluator).sub_inplace(res, product);
                        break;
                    }
                    case B_XOR_: {
                        Ciphertext product;
                        (*evaluator).multiply_plain(res, std::get<Plaintext>(stext), product);
                        (*evaluator).add_plain_inplace(res, std::get<Plaintext>(stext));
                        (*evaluator).sub_inplace(res, product);
                        (*evaluator).sub_inplace(res, product);
                        break;
                    }
                }
            }
            else { //If Ciphertext
                switch(op_hash(op)) {
                    case B_AND_: {
                        (*evaluator).multiply_inplace(res, std::get<Ciphertext>(stext));
                        break;
                    }    
                    case B_OR_: {
                        Ciphertext product;
                        (*evaluator).multiply(res, std::get<Ciphertext>(stext), product);
                        (*evaluator).add_inplace(res, std::get<Ciphertext>(stext));
                        (*evaluator).sub_inplace(res, product);
                        break;
                    }
                    case B_XOR_: {
                        Ciphertext product;
                        (*evaluator).multiply(res, std::get<Ciphertext>(stext), product);
                        (*evaluator).add_inplace(res, std::get<Ciphertext>(stext));
                        (*evaluator).sub_inplace(res, product);
                        (*evaluator).sub_inplace(res, product);
                        break;
                    }
                }
            }
        }
        result = res;
    }
    else {
        switch(op_hash(op)) {
            case IN_: {
				std::string var_name = input_texts[0];
				uint64_t value = params->at(var_name);
				int vis = std::stoi(input_texts[1]);

                Plaintext v_plain(util::uint_to_hex_string(&value, std::size_t(1)));  
                if (vis == ENCRYPTED) {
                    Ciphertext v_encrypted;
                    (*encryptor).encrypt(v_plain, v_encrypted);
                    result = v_encrypted;
                }
                else {
                    result = v_plain;
                }
				break;
			}
            case OUT_: {
                SealText output = cache->at(input_texts[0]);
                if (output.index() == 0) { //If Plaintext
                    std::cout << "0x" << (std::get<Plaintext>(output)).to_string() << std::endl;
                }
                else {
                    Ciphertext out = std::get<Ciphertext>(output);
                    Plaintext out_decrypted;
                    (*decryptor).decrypt(out, out_decrypted);
                    std::cout << out_decrypted.to_string() << std::endl;
                }
                break;
            }
        }
    }
    return result;
}

SealText process_bytecode(
    std::string bytecode_path, 
    std::unordered_map<std::string, SealText>* cache,
    std::unordered_map<std::string, uint32_t>* params,
    Encryptor *encryptor,
    Evaluator *evaluator,
    Decryptor *decryptor
) {
    std::ifstream file(bytecode_path);
	assert(("Bytecode file exists.", file.is_open()));
	if (!file.is_open()) throw std::runtime_error("Bytecode file doesn't exist -- "+bytecode_path);
	std::string str;
	SealText last_instr;

    while (std::getline(file, str)) {
        std::vector<std::string> line = split_(str, ' ');
        if (line.size() < 4) continue;
        int num_inputs = std::stoi(line[0]);
		int num_outputs = std::stoi(line[1]);
		std::vector<std::string> input_texts = std::vector<std::string>(num_inputs);
		std::vector<std::string> output_texts = std::vector<std::string>(num_outputs);

        for (int i = 0; i < num_inputs; i++) {
			input_texts[i] = line[2+i];
		}
		for (int i = 0; i < num_outputs; i++) {
			output_texts[i] = line[2+num_inputs+i];
		}

        std::string op = line[2+num_inputs+num_outputs];
        last_instr = process_instruction(encryptor, evaluator, decryptor, cache, params, input_texts, op);

        for (auto o: output_texts) {
            (*cache)[o] = last_instr;
        }
    }
    
    return last_instr;
}

void process_input_params(
    std::unordered_map<std::string, SealText>* cache,
    std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>>* params,
    SEALContext context,
    PublicKey public_key
) {
    Encryptor encryptor(context, public_key);
    for (auto p: *params) {
        std::string param_name = p.first;
        std::string param_role = std::get<0>(p.second);
        uint64_t param_value = std::get<1>(p.second);
		uint32_t param_index = std::get<2>(p.second);
        if (param_index == (uint32_t)-1) continue;

        SealText sealtext;

        Plaintext v_plain(util::uint_to_hex_string(&param_value, std::size_t(1)));    
        if (param_role == "client") {
            Ciphertext v_encrypted;
            encryptor.encrypt(v_plain, v_encrypted);
            sealtext = v_encrypted;
        }
        else {
            sealtext = v_plain;
        }

        (*cache)[std::to_string(param_index)] = sealtext;
    }
}

int32_t test_fhe(
    std::string bytecode_path,
    std::unordered_map<std::string, uint32_t>* params, 
    size_t poly_mod_deg,
    size_t plaintext_mod
) {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_mod_deg);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_mod_deg));
    parms.set_plain_modulus(plaintext_mod);
    SEALContext context(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key); 

    // Plain/Ciphertext Cache
    std::unordered_map<std::string, SealText>* cache 
        = new std::unordered_map<std::string, SealText>();

    SealText out = process_bytecode(bytecode_path, cache, params, &encryptor, &evaluator, &decryptor);

    delete cache;
    return 0;
}


/**************************************/
// Input Parsing and main()
/**************************************/
mode hash_mode(std::string m) {
    if (m == "fhe") return fhe;
    throw std::invalid_argument("Unknown mode: "+m);
}

std::vector<std::string> split(std::string str, char delimiter) {
    std::vector<std::string> result;
    std::istringstream ss(str);
    std::string word; 
    while (ss >> word) {
        result.push_back(word);
    }
    return result;
}

std::unordered_map<std::string, uint32_t> parse_fhe_inputs(std::string test_path) {
    std::ifstream file(test_path);
    assert(("Test file exists.", file.is_open()));
    if (!file.is_open()) throw std::runtime_error("Test file doesn't exist.");
    std::unordered_map<std::string, uint32_t> map;
    std::string str;
    
    while (std::getline(file, str)) {
        std::vector<std::string> line = split(str, ' ');
        std::string key_ = line[0];
        if (key_ == "res") continue;

        if (line.size() == 2) {
            std::string key = line[0];
            uint32_t value = (uint32_t)std::stoi(line[1]);
            map[key] = value;
        } else if (line.size() > 2) {
            for (int i = 1; i < line.size(); i++) {
                std::string key = line[0] + "_" + std::to_string(i-1);
                uint32_t value = (uint32_t)std::stoi(line[i]);
                map[key] = value;
            }
        }
    }
    return map;
}

int main(int argc, char** argv) {
    size_t poly_mod_deg = 4096;
    size_t plaintext_mod = 1024;

    argparse::ArgumentParser program("fhe_interpreter");
    program.add_argument("-M", "--mode").required().help("Mode for parsing test inputs");
    program.add_argument("-b", "--bytecode").required().help("Bytecode");
    program.add_argument("-t", "--test").required().help("Test inputs");
    //TODO: Change to encstatus map
    program.parse_args(argc, argv);    // Example: ./main --color orange

    std::string m, bytecode_path, test_path, share_map_path, param_map_path;
    m = program.get<std::string>("--mode");  
    //role = !program.get<int>("--role") ? SERVER : CLIENT;
    bytecode_path = program.get<std::string>("--bytecode");
    test_path = program.get<std::string>("--test");

    std::unordered_map<std::string, uint32_t> params;
	switch(hash_mode(m)) {
        case fhe: {
            params = parse_fhe_inputs(test_path);
        }
        break;
    }

	test_fhe(bytecode_path, &params, poly_mod_deg, plaintext_mod);

	return 0;
}