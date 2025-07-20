#pragma once

#include <format>
#include <string>

std::string open_error_to_string(int code);
std::string send_error_to_string(int code);
std::string recv_error_to_string(int code);