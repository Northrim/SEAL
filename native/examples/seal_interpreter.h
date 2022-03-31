#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
using namespace seal;

int32_t test_fhe(
    std::string bytecode_path,
    std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>>* params, 
    size_t poly_mod_deg,
    size_t plaintext_mod
);