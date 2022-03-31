#include "../../examples.h"
using namespace seal;

int32_t test_fhe(
    std::string bytecode_path,
    std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>>* params, 
    size_t poly_mod_deg,
    size_t plaintext_mod
);