#include "seal_interpreter.h"

enum op {
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
	OUT_,
};

op op_hash(std::string o) {
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
	if (o == "OUT") return OUT_;
    throw std::invalid_argument("Unknown operator: "+o);
}

int32_t test_fhe(
    std::string bytecode_path,
    std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>>* params, 
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
}