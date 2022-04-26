#include "seal_interpreter.h"
#include "argparse.hpp"
#include "examples.h"
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
    V_AND_,
    V_OR_,
    V_XOR_,
    ADD_,
    MUL_,
    CONS_,
    ARR_CONS_,
    B_EQ_,
    IN_,
    ARR_IN_,
	OUT_,
    ARR_OUT_,
};

op op_hash(std::string o) {
    if (o == "B_AND") return B_AND_;
    if (o == "B_OR") return B_OR_;
    if (o == "B_XOR") return B_XOR_;
    if (o == "V_AND") return V_AND_;
    if (o == "V_OR") return V_OR_;
    if (o == "V_XOR") return V_XOR_;
    if (o == "ADD") return ADD_;
    if (o == "MUL") return MUL_;
    if (o == "CONS") return CONS_;
    if (o == "ARR_CONS") return ARR_CONS_;
    if (o == "B_EQ") return B_EQ_;
    if (o == "IN") return IN_;
    if (o == "ARR_IN") return ARR_IN_;
	if (o == "OUT") return OUT_;
    if (o == "ARR_OUT") return ARR_OUT_;
    throw std::invalid_argument("Unknown operator: "+o);
}

bool is_boolnary_op(op o) {
    return o == B_AND_ || o == B_OR_ || o == B_XOR_;
}

bool is_bvnary_op(op o) {
    return o == V_AND_ || o == V_OR_ || o == V_XOR_ || o == ADD_ || o == MUL_;
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
		throw std::invalid_argument("Unknown stext in cache: " + key);
	}
	else {
		return sealtext->second;
	}
}

Ciphertext get_ciphertext(SealText s, Encryptor* encryptor) {
    Ciphertext res;
    if (s.index() == 0)
        (*encryptor).encrypt(std::get<Plaintext>(s), res);
    else
        res = std::get<Ciphertext>(s);
    return res;
}

Plaintext new_ptext(uint32_t value, BatchEncoder* batch_encoder) {
    size_t slot_count = batch_encoder->slot_count();
    std::vector<uint64_t> pod_vector(slot_count, 0ULL);
    pod_vector[0] = value;
    Plaintext v_plain;
    batch_encoder->encode(pod_vector, v_plain);
    return v_plain;
}

Plaintext new_ptext_vec(std::vector<uint32_t> values, BatchEncoder* batch_encoder) {
    size_t slot_count = batch_encoder->slot_count();
    std::vector<uint64_t> pod_vector(slot_count, 0ULL);
    for(int i = 0; i < values.size(); i++) {
        pod_vector[i] = values[i];
    }
    Plaintext v_plain;
    batch_encoder->encode(pod_vector, v_plain);
    return v_plain;
}

Ciphertext new_ctext(uint32_t value, Encryptor* encryptor, BatchEncoder* batch_encoder) {
    Plaintext v_plain = new_ptext(value, batch_encoder);
    Ciphertext v_encrypted;
    (*encryptor).encrypt(v_plain, v_encrypted);
    return v_encrypted;
}

Ciphertext new_ctext_vec(std::vector<uint32_t> values, Encryptor* encryptor, BatchEncoder* batch_encoder) {
    Plaintext v_plain = new_ptext_vec(values, batch_encoder);
    Ciphertext v_encrypted;
    (*encryptor).encrypt(v_plain, v_encrypted);
    return v_encrypted;
}

SealText process_instruction(
    Encryptor* encryptor,
    Evaluator* evaluator,
    Decryptor* decryptor,
    BatchEncoder *batch_encoder,
    std::unordered_map<std::string, SealText>* cache,
    std::unordered_map<std::string, std::vector<uint32_t>>* params,
    std::vector<std::string> input_texts, 
    std::string op
) {
    SealText result;

    if (is_boolnary_op(op_hash(op))) {
        SealText s0 = get_from_cache(cache, input_texts[0]);
        Ciphertext res = get_ciphertext(s0, encryptor);
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
    else if (is_bvnary_op(op_hash(op))) {
        SealText s0 = get_from_cache(cache, input_texts[0]);
        Ciphertext res = get_ciphertext(s0, encryptor);
        
        for (auto it = ++input_texts.begin(); it != input_texts.end(); it++) {
            SealText stext = get_from_cache(cache, *it);
            if (stext.index() == 0) { //If Plaintext
                switch(op_hash(op)) {
                    case V_AND_: {
                        break;
                    }    
                    case V_OR_: {
                        break;
                    }
                    case B_XOR_: {
                        break;
                    }
                    case ADD_: {
                        (*evaluator).add_plain_inplace(res, std::get<Plaintext>(stext));
                        break;
                    }
                    case MUL_: {
                        (*evaluator).multiply_plain_inplace(res, std::get<Plaintext>(stext));
                        break;
                    }
                }
            }
            else { //If Ciphertext
                switch(op_hash(op)) {
                    case V_AND_: {
                        break;
                    }    
                    case V_OR_: {
                        break;
                    }
                    case B_XOR_: {
                        break;
                    }
                    case ADD_: {
                        (*evaluator).add_inplace(res, std::get<Ciphertext>(stext));
                        break;
                    }
                    case MUL_: {
                        (*evaluator).multiply_inplace(res, std::get<Ciphertext>(stext));
                        break;
                    }
                }
            }
        }
        result = res;
    }
    else {
        switch(op_hash(op)) {
            case CONS_: {
                uint32_t value = std::stoi(input_texts[0]);
                result = new_ctext(value, encryptor, batch_encoder);
                break;
            }
            case ARR_CONS_: {
                std::vector<uint32_t> values;
                for (auto i : input_texts) {
                    values.push_back(std::stoi(i));
                }
                result = new_ctext_vec(values, encryptor, batch_encoder);
                break;
            }
            case B_EQ_: {
                Ciphertext res = new_ctext(1, encryptor, batch_encoder);
                SealText s0 = get_from_cache(cache, input_texts[0]);
                Ciphertext c0 = get_ciphertext(s0, encryptor);

                SealText s1 = get_from_cache(cache, input_texts[1]);
                if (s1.index() == 0) { //If Plaintext
                    Ciphertext product;
                    (*evaluator).multiply_plain(c0, std::get<Plaintext>(s1), product);
                    (*evaluator).sub_inplace(res, c0);
                    (*evaluator).sub_plain_inplace(res, std::get<Plaintext>(s1));
                    (*evaluator).add_inplace(res, product);
                    (*evaluator).add_inplace(res, product);
                }
                else { //If Ciphertext
                    Ciphertext product;
                    (*evaluator).multiply(c0, std::get<Ciphertext>(s1), product);
                    (*evaluator).sub_inplace(res, c0);
                    (*evaluator).sub_inplace(res, std::get<Ciphertext>(s1));
                    (*evaluator).add_inplace(res, product);
                    (*evaluator).add_inplace(res, product);
                }
                result = res;
                break;
            }
            case IN_: {
				std::string var_name = input_texts[0];
				uint32_t value = (params->at(var_name))[0];
				int vis = std::stoi(input_texts[1]);

                if (vis == PLAIN) 
                    result = new_ptext(value, batch_encoder);
                else
                    result = new_ctext(value, encryptor, batch_encoder);
				break;
			}
            case ARR_IN_: {
                std::string var_name = input_texts[0];
                std::vector<uint32_t> values = params->at(var_name);
                int vis = std::stoi(input_texts[1]);
                int len = std::stoi(input_texts[2]);
                if (len != values.size())
                    throw std::invalid_argument("Array input length incorrect");

                if (vis == PLAIN)
                    result = new_ptext_vec(values, batch_encoder);
                else
                    result = new_ctext_vec(values, encryptor, batch_encoder);
                break;
            }
            case OUT_: {
                std::vector<uint64_t> pod_vector(batch_encoder->slot_count(), 0ULL);
                SealText output = cache->at(input_texts[0]);
                if (output.index() == 0) { //If Plaintext
                    Plaintext plain_result = std::get<Plaintext>(output);
                    batch_encoder->decode(plain_result, pod_vector);
                }
                else {
                    Ciphertext out = std::get<Ciphertext>(output);
                    Plaintext plain_result;
                    (*decryptor).decrypt(out, plain_result);
                    batch_encoder->decode(plain_result, pod_vector);
                }
                std::cout << pod_vector[0] << std::endl;
                break;
            }
            case ARR_OUT_: {
                std::vector<uint64_t> pod_vector(batch_encoder->slot_count(), 0ULL);
                SealText output = cache->at(input_texts[0]);
                int len = std::stoi(input_texts[1]);
                if (output.index() == 0) { //If Plaintext
                    Plaintext plain_result = std::get<Plaintext>(output);
                    batch_encoder->decode(plain_result, pod_vector);
                }
                else {
                    Ciphertext out = std::get<Ciphertext>(output);
                    Plaintext plain_result;
                    (*decryptor).decrypt(out, plain_result);
                    batch_encoder->decode(plain_result, pod_vector);
                }
                
                for (int i = 0; i < len; i++) {
                    std::cout << pod_vector[i] << " ";
                }
                std::cout << std::endl;
                break;
            }
        }
    }
    return result;
}

SealText process_bytecode(
    std::string bytecode_path, 
    std::unordered_map<std::string, SealText>* cache,
    std::unordered_map<std::string, std::vector<uint32_t>>* params,
    Encryptor *encryptor,
    Evaluator *evaluator,
    Decryptor *decryptor,
    BatchEncoder *batch_encoder
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
        last_instr = process_instruction(encryptor, evaluator, decryptor, batch_encoder,
            cache, params, input_texts, op);
        for (auto o: output_texts) {
            (*cache)[o] = last_instr;
        }
    }
    
    return last_instr;
}

int32_t test_fhe(
    std::string bytecode_path,
    std::unordered_map<std::string, std::vector<uint32_t>>* params, 
    size_t poly_mod_deg
) {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_mod_deg);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_mod_deg));
    parms.set_plain_modulus(PlainModulus::Batching(poly_mod_deg, 20));
    SEALContext context(parms);
    //print_parameters(context);
    std::cout << std::endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key); 
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();

    // Plain/Ciphertext Cache
    std::unordered_map<std::string, SealText>* cache 
        = new std::unordered_map<std::string, SealText>();

    SealText out = process_bytecode(bytecode_path, cache, params, 
        &encryptor, &evaluator, &decryptor, &batch_encoder);

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

std::unordered_map<std::string, std::vector<uint32_t>> parse_fhe_inputs(std::string test_path) {
    std::ifstream file(test_path);
    assert(("Test file exists.", file.is_open()));
    if (!file.is_open()) throw std::runtime_error("Test file doesn't exist.");
    std::unordered_map<std::string, std::vector<uint32_t>> map;
    std::string str;
    
    while (std::getline(file, str)) {
        std::vector<std::string> line = split(str, ' ');
        std::string key_ = line[0];
        if (key_ == "res") continue;

        if (key_ == "arr")  {
            std::string key = line[1];
            std::vector<uint32_t> values;
            for (int i = 2; i < line.size(); i++) {
                values.push_back((uint32_t)std::stoi(line[i]));
            }
            map[key] = values;
            continue;
        }

        if (line.size() == 2) {
            std::string key = line[0];
            std::vector<uint32_t> values = {(uint32_t)std::stoi(line[1])};
            map[key] = values;
        } else if (line.size() > 2) {
            for (int i = 1; i < line.size(); i++) {
                std::string key = line[0] + "_" + std::to_string(i-1);
                std::vector<uint32_t> values = {(uint32_t)std::stoi(line[i])};
                map[key] = values;
            }
        }
    }
    return map;
}

int main(int argc, char** argv) {
    size_t poly_mod_deg = 8192;

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

    std::unordered_map<std::string, std::vector<uint32_t>> params;
	switch(hash_mode(m)) {
        case fhe: {
            params = parse_fhe_inputs(test_path);
        }
        break;
    }

	test_fhe(bytecode_path, &params, poly_mod_deg);

	return 0;
}