#include "pch.h"
#include "utils.h"
#include <charconv>
#include <format>
#include <codecvt>
#include <string>
#include <sstream>
#include <Windows.h>
#include <algorithm>

namespace netcure::utils {

	ip_addr::~ip_addr() = default;

	ipv4_addr::ipv4_addr(std::string_view addr) {
		size_t pos = 0;
		for (int i = 0; i < 4; ++i) {
			size_t next_pos = addr.find('.', pos);
			if (next_pos == std::string::npos && i < 3) {
				throw std::invalid_argument("Invalid IPv4 address format");
			}
			auto part = addr.substr(pos, next_pos - pos);
			if (auto result = std::from_chars(part.data(), part.data() + part.size(), addr_[i]); result.ec != std::errc() || result.ptr != part.data() + part.size()) {
				throw std::invalid_argument("Invalid IPv4 address part");
			}
			pos = next_pos + 1;
		}
	}

	std::string ipv4_addr::to_string() const {
		return std::format("{}.{}.{}.{}", addr_[0], addr_[1], addr_[2], addr_[3]);
	}

	ipv4_addr::operator std::string() const {
		return to_string();
	}

	ipv6_addr::ipv6_addr(std::string_view addr) {
		std::fill(std::begin(addr_), std::end(addr_), uint8_t{0});
		size_t double_colon = addr.find("::");
		std::vector<std::string_view> parts;
		if (double_colon != std::string_view::npos) {
			std::string_view left = addr.substr(0, double_colon);
			std::string_view right = addr.substr(double_colon + 2);
			size_t pos = 0, next;
			while ((next = left.find(':', pos)) != std::string_view::npos) {
				if (next > pos)
					parts.push_back(left.substr(pos, next - pos));
				pos = next + 1;
			}
			if (pos < left.size())
				parts.push_back(left.substr(pos));
			size_t left_count = parts.size();
			std::vector<std::string_view> right_parts;
			pos = 0;
			while ((next = right.find(':', pos)) != std::string_view::npos) {
				if (next > pos)
					right_parts.push_back(right.substr(pos, next - pos));
				pos = next + 1;
			}
			if (pos < right.size())
				right_parts.push_back(right.substr(pos));
			size_t right_count = right_parts.size();
			if (left_count + right_count > 8)
				throw std::invalid_argument("Invalid IPv6 address: too many segments");
			size_t idx = 0;
			for (const auto& part : parts) {
				if (part.empty()) continue;
				uint16_t val = 0;
				auto result = std::from_chars(part.data(), part.data() + part.size(), val, 16);
				if (result.ec != std::errc() || result.ptr != part.data() + part.size())
					throw std::invalid_argument("Invalid IPv6 segment");
				addr_[idx * 2] = static_cast<uint8_t>(val >> 8);
				addr_[idx * 2 + 1] = static_cast<uint8_t>(val & 0xFF);
				++idx;
			}
			idx = 8 - right_count;
			for (const auto& part : right_parts) {
				if (part.empty()) continue;
				uint16_t val = 0;
				auto result = std::from_chars(part.data(), part.data() + part.size(), val, 16);
				if (result.ec != std::errc() || result.ptr != part.data() + part.size())
					throw std::invalid_argument("Invalid IPv6 segment");
				addr_[idx * 2] = static_cast<uint8_t>(val >> 8);
				addr_[idx * 2 + 1] = static_cast<uint8_t>(val & 0xFF);
				++idx;
			}
		} else {
			size_t next, pos = 0;
			while ((next = addr.find(':', pos)) != std::string_view::npos) {
				if (next > pos)
					parts.push_back(addr.substr(pos, next - pos));
				else
					parts.push_back("");
				pos = next + 1;
			}
			if (pos < addr.size())
				parts.push_back(addr.substr(pos));
			if (parts.size() != 8)
				throw std::invalid_argument("Invalid IPv6 address: must have 8 segments");
			for (size_t i = 0; i < 8; ++i) {
				const auto& part = parts[i];
				uint16_t val = 0;
				auto result = std::from_chars(part.data(), part.data() + part.size(), val, 16);
				if (result.ec != std::errc() || result.ptr != part.data() + part.size())
					throw std::invalid_argument("Invalid IPv6 segment");
				addr_[i * 2] = static_cast<uint8_t>(val >> 8);
				addr_[i * 2 + 1] = static_cast<uint8_t>(val & 0xFF);
			}
		}
	}

	std::string ipv6_addr::to_string() const {
		int best_start = -1, best_len = 0;
		for (int i = 0; i < 8;) {
			int j = i;
			while (j < 8 && addr_[j * 2] == 0 && addr_[j * 2 + 1] == 0) ++j;
			if (j - i > best_len && j - i > 1) {
				best_start = i;
				best_len = j - i;
			}
			i = (j == i) ? i + 1 : j;
		}
		std::string result;
		for (int i = 0; i < 8;) {
			if (i == best_start) {
				result += "::";
				i += best_len;
				if (i == 8) break;
			} else {
				if (!result.empty() && result.back() != ':')
					result += ":";
				uint16_t val = (static_cast<uint16_t>(addr_[i * 2]) << 8) | addr_[i * 2 + 1];
				result += std::format("{:x}", val);
				++i;
			}
		}
		return result;
	}

	ipv6_addr::operator std::string() const {
		return to_string();
	}

	std::unique_ptr<ip_addr> parse_ip(std::string_view addr) {
		if (addr.contains(':')) {
			return std::make_unique<ipv6_addr>(addr);
		} else {
			return std::make_unique<ipv4_addr>(addr);
		}
	}

	cidr::cidr(std::string_view cidr_str) {
		auto pos = cidr_str.find('/');
		if (pos == std::string_view::npos) {
			throw std::invalid_argument("Invalid CIDR format");
		}
		addr = parse_ip(cidr_str.substr(0, pos));
		if (auto result = std::from_chars(cidr_str.data() + pos + 1, cidr_str.data() + cidr_str.size(), prefix_length); result.ec != std::errc() || result.ptr != cidr_str.data() + cidr_str.size()) {
			throw std::invalid_argument("Invalid CIDR prefix length");
		}
	}

	cidr::cidr(std::unique_ptr<ip_addr> ipaddr, uint8_t prefix_length)
		: addr(std::move(ipaddr)), prefix_length(prefix_length) {
		if (dynamic_cast<ipv4_addr*>(addr.get()) && prefix_length > 32) {
			throw std::invalid_argument("CIDR prefix length for IPv4 must be between 0 and 32");
		} else if (prefix_length > 128) {
			throw std::invalid_argument("CIDR prefix length for IPv6 must be between 0 and 128");
		}
	}

	std::string cidr::to_string() const {
		return std::format("{}/{}", addr->to_string(), prefix_length);
	}

	cidr::operator std::string() const {
		return to_string();
	}

	bool cidr::contains(const ip_addr* ip) const {
		if (!ip) {
			return false;
		}
		// TODO
		if (const auto* v4addr = dynamic_cast<const ipv4_addr*>(ip)) {
			if (const auto* v4cidr = dynamic_cast<const ipv4_addr*>(addr.get())) {
				
			}
			return false;
		} else if (const auto* v6addr = dynamic_cast<const ipv6_addr*>(ip)) {
			if (const auto* v6cidr = dynamic_cast<const ipv6_addr*>(addr.get())) {
				
			}
			return false;
		}
		return false;
	}

	mac::mac(std::string_view mac_bytes) {
		if (mac_bytes.size() != 0)
			addr_ = std::string(mac_bytes);
	}

	std::string mac::to_string() const {
		std::stringstream ss;
		
		for (size_t i = 0; i < addr_.size(); ++i) {
			if (i > 0) {
				ss << ':';
			}
			ss << std::format("{:02x}", static_cast<unsigned char>(addr_[i]));
		}

		return ss.str();
	}

	mac::operator std::string() const {
		return to_string();
	}

	bool mac::empty() const {
		return addr_.empty() || std::all_of(addr_.begin(), addr_.end(), [](char c) {
			return c == 0;
		});
	}

	std::string to_string(const std::wstring& str) {
		if (str.empty())
		{
			return "";
		}
		const auto size_needed = WideCharToMultiByte(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0, nullptr, nullptr);
		if (size_needed <= 0)
		{
			throw std::runtime_error("WideCharToMultiByte() failed: " + std::to_string(size_needed));
		}
		std::string result;
		result.resize(size_needed);
		WideCharToMultiByte(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), result.data(), size_needed, nullptr, nullptr);
		return result;
	}
}