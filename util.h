#pragma once
#ifndef UTIL_HEADER
#define UTIL_HEADER

#include <Windows.h>
#include <string>
#include <vector>
#include <format>
#include <filesystem>
#include <iostream>
#include <fstream>

using namespace std;
using String = std::string;
namespace fs = std::filesystem;

template<class T>
using List = std::vector<T>;

#endif