#pragma once

#include <vector>
#include <cstdint>
#include <string>

bool CompileTextPolicy(const wchar_t* path, std::vector<uint8_t>& binaryPolicy, std::wstring& error);
