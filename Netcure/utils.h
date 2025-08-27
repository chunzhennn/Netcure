#pragma once
#ifndef NETCURE_UTILS_H
#define NETCURE_UTILS_H

#include <string>
#include <variant>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <memory>
#include <vector>
#include <array>
#include <span>
#include <charconv>
#include <utility>
#include <format>

#ifdef WIN32
#include <Windows.h>
#include <WinSock2.h>
#include <ifdef.h>

using if_id_type = IF_LUID;
#else
static_assert(false, "Platform not supported");
#endif

namespace netcure::utils {
	struct ip_addr {
		virtual ~ip_addr();
		virtual std::string to_string() const = 0;
		virtual operator std::string() const = 0;
		virtual const uint8_t* data() const = 0;
		virtual uint8_t* data() = 0;
		virtual size_t size() const = 0;
		bool operator==(const ip_addr& other) const {
			if (typeid(*this) != typeid(other)) {
				return false;
			}
			return this->size() == other.size() && std::equal(this->data(), this->data() + this->size(), other.data());
		}
	};

	struct ipv4_addr final : ip_addr {
		ipv4_addr() {
			std::fill_n(addr_, sizeof(addr_), static_cast<uint8_t>(0));
		}
		explicit ipv4_addr(std::string_view addr);
		ipv4_addr(const ipv4_addr& other) {
			std::memcpy(addr_, other.addr_, sizeof(addr_));
		};
		virtual std::string to_string() const;
		virtual operator std::string() const;
		virtual const uint8_t* data() const {
			return addr_;
		}
		virtual uint8_t* data() {
			return addr_;
		}
		virtual size_t size() const {
			return sizeof(addr_);
		}
		bool operator==(const ipv4_addr& other) const {
			return std::equal(std::begin(addr_), std::end(addr_), std::begin(other.addr_));
		}
	private:
		uint8_t addr_[4];
	};

	struct ipv6_addr final : ip_addr {
		ipv6_addr() {
			std::fill_n(addr_, sizeof(addr_), static_cast<uint8_t>(0));
		}
		explicit ipv6_addr(std::string_view addr);
		ipv6_addr(const ipv6_addr& other) {
			std::memcpy(addr_, other.addr_, sizeof(addr_));
		};
		virtual std::string to_string() const;
		virtual operator std::string() const;
		virtual const uint8_t* data() const {
			return addr_;
		}
		virtual uint8_t* data() {
			return addr_;
		}
		virtual size_t size() const {
			return sizeof(addr_);
		}
		bool operator==(const ipv6_addr& other) const {
			return std::equal(std::begin(addr_), std::end(addr_), std::begin(other.addr_));
		}
	private:
		uint8_t addr_[16];
	};

	template<typename T>
	requires std::derived_from<T, ip_addr>
	struct cidr {
		T addr;
		uint8_t prefix_length;
		explicit cidr(std::string_view cidr_str) {
			auto pos = cidr_str.find('/');
			if (pos == std::string_view::npos) {
				throw std::invalid_argument("Invalid CIDR format");
			}
			addr = T{ cidr_str.substr(0, pos) };
			if (auto result = std::from_chars(cidr_str.data() + pos + 1, cidr_str.data() + cidr_str.size(), prefix_length); result.ec != std::errc() || result.ptr != cidr_str.data() + cidr_str.size()) {
				throw std::invalid_argument("Invalid CIDR prefix length");
			}
		}
		explicit cidr(auto&& ipaddr, uint8_t prefix_length) : addr{ std::forward<T>(ipaddr) } {
			this->prefix_length = prefix_length;
			if (prefix_length > ipaddr.size() * 8) {
				throw std::invalid_argument("CIDR prefix length out of range");
			}
		}
		std::string to_string() const {
			return std::format("{}/{}", static_cast<std::string>(addr), prefix_length);
		};
		operator std::string() const {
			return to_string();
		}
		bool contains(const T& ip) const {
			std::span<const uint8_t> addr_span(addr.data(), addr.size());
			std::span<const uint8_t> ip_span(ip.data(), ip.size());
			size_t full_bytes = prefix_length / 8;
			size_t remaining_bits = prefix_length % 8;
			if (addr.size() != ip.size()) {
				return false;
			}
			if (!std::equal(addr_span.begin(), addr_span.begin() + full_bytes, ip_span.begin())) {
				return false;
			}
			if (remaining_bits > 0) {
				uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remaining_bits));
				if ((addr_span[full_bytes] & mask) != (ip_span[full_bytes] & mask)) {
					return false;
				}
			}
			return true;
		}
		bool operator==(const cidr<T>& other) const {
			return prefix_length == other.prefix_length && addr == other.addr;
		}
	};

	struct mac {
		mac() = default;
		explicit mac(std::string_view);
		std::string to_string() const;
		operator std::string() const;
		bool empty() const;
		bool operator==(const mac& other) const {
			return addr_ == other.addr_;
		}
	private:
		std::string addr_;
	};

	struct network_interface {
		if_id_type id;
		std::string name;
		mac mac_address;
		bool up = false;
		std::vector<cidr<ipv4_addr>> ipv4_addresses;
		std::vector<ipv4_addr> gateway4_addresses;
		std::vector<ipv4_addr> dns4_addresses;
		std::vector<cidr<ipv6_addr>> ipv6_addresses;
		std::vector<ipv6_addr> gateway6_addresses;
		std::vector<ipv6_addr> dns6_addresses;

		bool is_virtual() const;
	};

	template<typename T>
		requires std::derived_from<T, ip_addr>
	struct route_entry {
		cidr<T> destination;
		T next_hop;
		std::string interface;
		if_id_type interface_id;
		size_t metric = 0;
	};

	std::string to_string(const std::wstring& str);
}

#endif // NETCURE_UTILS_H