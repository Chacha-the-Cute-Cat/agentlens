#pragma once

#include <vector>
#include <cstdint>

bool LoadPolicyFile(const wchar_t* path, std::vector<uint8_t>& policy);
