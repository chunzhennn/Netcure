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

namespace netcure::utils {
	struct ip_addr {
		virtual ~ip_addr();
		virtual std::string to_string() const = 0;
		virtual operator std::string() const = 0;
		bool operator==(const ip_addr& other) const {
			if (typeid(*this) != typeid(other)) {
				return false;
			}
			// We don't know the exact type, so we use to_string for comparison
			return this->to_string() == other.to_string();
		}
	};

	struct ipv4_addr final : ip_addr {
		friend class cidr;
		explicit ipv4_addr(std::string_view addr);
		std::string to_string() const override;
		operator std::string() const override;
		bool operator==(const ipv4_addr& other) const {
			return std::equal(std::begin(addr_), std::end(addr_), std::begin(other.addr_));
		}
	private:
		uint8_t addr_[4];
	};

	struct ipv6_addr final : ip_addr {
		friend class cidr;
		explicit ipv6_addr(std::string_view addr);
		std::string to_string() const override;
		operator std::string() const override;
		bool operator==(const ipv6_addr& other) const {
			return std::equal(std::begin(addr_), std::end(addr_), std::begin(other.addr_));
		}
	private:
		uint8_t addr_[16];
	};

	std::unique_ptr<ip_addr> parse_ip(std::string_view addr);

	struct cidr {
		std::unique_ptr<ip_addr> addr;
		uint8_t prefix_length;
		explicit cidr(std::string_view cidr_str);
		explicit cidr(std::unique_ptr<ip_addr> ipaddr, uint8_t prefix_length);
		std::string to_string() const;
		operator std::string() const;
		bool contains(const ip_addr*) const;
		bool operator==(const cidr& other) const {
			return prefix_length == other.prefix_length && *addr == *other.addr;
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
		std::string name;
		mac mac_address;
		bool up = false;
		std::vector<cidr> ipv4_addresses;
		std::vector<ipv4_addr> gateway4_addresses;
		std::vector<ipv4_addr> dns4_addresses;
		std::vector<cidr> ipv6_addresses;
		std::vector<ipv6_addr> gateway6_addresses;
		std::vector<ipv6_addr> dns6_addresses;
	};

	struct route_entry {
		cidr destination;
		std::unique_ptr<ip_addr> next_hop;
		// Due to API limitations(?), we store the interface as a string
		std::string interface;
		size_t metric = 0;
	};

	std::string to_string(const std::wstring& str);
}

#endif // NETCURE_UTILS_H