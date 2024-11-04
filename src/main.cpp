#include <filesystem>
#include <iostream>
#include <span>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <vector>

#include "absl/flags/usage.h"
#include <absl/flags/flag.h>
#include <absl/flags/parse.h>
#include <absl/log/globals.h>
#include <absl/log/initialize.h>
#include <absl/log/log.h>
#include <absl/status/statusor.h>
#include <absl/strings/escaping.h>
#include <absl/strings/numbers.h>
#include <absl/strings/str_format.h>
#include <absl/time/time.h>
#include <sodium.h>
#include <toml++/toml.h>

constexpr size_t kDefaultSaltSize = 32;
constexpr size_t kDefaultSeedSize = 32;

enum class AlgorithmType {
    RFC6238,
    HMAC_SHA256,
};

enum class OutputFormat {
    Hex,
    Base64,
};

struct ScryptParams {
    uint64_t opslimit;
    uint64_t memlimit;
};

struct TOTPConfig {
    std::string name;
    std::vector<uint8_t> enc_seed;
    uint32_t crc;
    absl::Duration interval = absl::Seconds(30);
    std::vector<uint8_t> salt;
    AlgorithmType algorithm;
    ScryptParams scrypt_params;
};

std::string bytes_to_hex_string(std::span<uint8_t const> data) {
    return absl::BytesToHexString(absl::string_view(
            reinterpret_cast<char const *>(data.data()), data.size()));
}

void print_bytes(
        std::span<uint8_t const> bytes, OutputFormat format, std::ostream &os) {
    switch (format) {
        case OutputFormat::Hex:
            os << bytes_to_hex_string(bytes) << std::endl;
            break;
        case OutputFormat::Base64:
            os << absl::Base64Escape(absl::string_view(
                    reinterpret_cast<char const *>(bytes.data()), bytes.size()))
               << std::endl;
            break;
    }
}

template<typename T>
absl::optional<T> parse_numeric(std::string const &input) {
    T result;
    return absl::SimpleAtoi(input, &result) ? absl::make_optional(result)
                                            : absl::nullopt;
}

absl::optional<std::string> prompt_password() {
    termios oldt{}, newt{};
    std::string password;

    std::cerr << "Enter password: ";

    if (tcgetattr(STDIN_FILENO, &oldt) != 0)
        return absl::nullopt;
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0)
        return absl::nullopt;
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
    return password;
}

std::vector<uint8_t> prompt_hex_or_random(
        size_t len, std::string const &prompt_text) {
    std::string hex_input;
    std::cout << prompt_text << " (or press Enter for random): ";
    std::getline(std::cin, hex_input);
    std::vector<uint8_t> result(len);

    if (hex_input.empty()) {
        randombytes_buf(result.data(), len);
    } else {
        std::string parsed_bytes;
        if (absl::HexStringToBytes(hex_input, &parsed_bytes)
                && parsed_bytes.size() == len) {
            std::copy(parsed_bytes.begin(), parsed_bytes.end(), result.begin());
        } else {
            LOG(WARNING) << "Invalid hex input or incorrect length. Generating "
                            "random data.";
            randombytes_buf(result.data(), len);
        }
    }
    return result;
}

void encrypt_seed(std::vector<uint8_t> const &seed,
        std::vector<uint8_t> const &key,
        std::vector<uint8_t> &encrypted_seed) {
    encrypted_seed.resize(seed.size());
    for (size_t i = 0; i < seed.size(); ++i) {
        encrypted_seed[i] = seed[i] ^ key[i % key.size()];
    }
}

// best effort

uint64_t calculate_pwhash_opslimit(absl::Duration const &target_duration) {
    return 22369621.3 * absl::ToDoubleSeconds(target_duration);
}

uint64_t calculate_pwhash_memlimit(size_t target_mem_mb) {
    return 2147483.65 * target_mem_mb;
}

absl::StatusOr<std::vector<uint8_t>> derive_key(std::string_view password,
        std::span<uint8_t const> salt,
        size_t key_size,
        ScryptParams const &params) {
    std::vector<uint8_t> key(key_size);

    if (crypto_pwhash_scryptsalsa208sha256(key.data(),
                key_size,
                password.data(),
                password.size(),
                salt.data(),
                params.opslimit,
                params.memlimit)
            != 0) {
        return absl::InternalError("Failed to derive key");
    }

    return key;
}

absl::StatusOr<absl::Duration> parse_duration(std::string_view prompt,
        std::optional<absl::Duration> default_duration) {
    std::string input;
    absl::Duration duration;

    std::cerr << prompt;
    std::getline(std::cin, input);

    if (input.empty() && default_duration)
        return default_duration.value();

    if (!absl::ParseDuration(input, &duration))
        return absl::InvalidArgumentError("Invalid duration");

    return duration;
}

uint32_t crc32(std::span<uint8_t const> data) {
    return static_cast<uint32_t>(absl::ComputeCrc32c(absl::string_view(
            reinterpret_cast<char const *>(data.data()), data.size())));
}

absl::StatusOr<TOTPConfig> build_config_interactive(
        OutputFormat output_format) {
    TOTPConfig config;

    std::cout << "Enter name: ";
    std::getline(std::cin, config.name);
    if (config.name.empty())
        return absl::InvalidArgumentError("Name cannot be empty");

    size_t salt_len = parse_numeric<size_t>("Enter salt size (default 32): ")
                              .value_or(kDefaultSaltSize);
    config.salt = prompt_hex_or_random(salt_len, "Enter salt as hexadecimal");

    absl::StatusOr<absl::Duration> pwhash_duration = parse_duration(
            "Enter pwhash expected duration (default ~1s): ", absl::Seconds(1));

    if (!pwhash_duration.ok())
        return pwhash_duration.status();

    config.interval = absl::Seconds(
            parse_numeric<int>("Enter interval in seconds (default is 30): ")
                    .value_or(30));

    std::cout << "Select algorithm\n";
    std::cout << "1) RFC6238\t2) HMAC-SHA256\n";
    std::string algo_input;
    std::getline(std::cin, algo_input);

    if (algo_input == "1") {
        config.algorithm = AlgorithmType::RFC6238;
    } else if (algo_input == "2") {
        config.algorithm = AlgorithmType::HMAC_SHA256;
    } else {
        return absl::InvalidArgumentError("Invalid algorithm");
    }

    auto password = prompt_password();
    if (!password)
        return absl::InvalidArgumentError("Failed to get password");

    size_t seed_len = parse_numeric<size_t>("Enter seed size (default 32): ")
                              .value_or(kDefaultSeedSize);
    if (seed_len == 0)
        return absl::InvalidArgumentError(
                "Seed size must be greater than zero");

    std::vector<uint8_t> seed =
            prompt_hex_or_random(seed_len, "Enter seed as hexadecimal");

    config.crc = crc32(seed);

    config.scrypt_params =
            ScryptParams{calculate_pwhash_opslimit(pwhash_duration.value()),
                    calculate_pwhash_memlimit(512)};

    auto key =
            derive_key(*password, config.salt, seed_len, config.scrypt_params);

    if (!key.ok())
        return key.status();

    print_bytes(seed, output_format, std::cout);
    encrypt_seed(seed, *key, config.enc_seed);

    sodium_memzero(password->data(), password->size());
    sodium_memzero(seed.data(), seed.size());

    return config;
}

std::vector<uint8_t> hmac_sha256(
        std::vector<uint8_t> const &key, std::vector<uint8_t> const &data) {
    std::vector<uint8_t> result(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256(result.data(), data.data(), data.size(), key.data());
    return result;
}

std::vector<uint8_t> generate_totp_hmac_sha256(std::vector<uint8_t> const &seed,
        size_t num_bytes,
        absl::Duration const &interval) {
    uint64_t time =
            absl::ToUnixSeconds(absl::Now()) / absl::ToDoubleSeconds(interval);
    std::vector<uint8_t> time_bytes(sizeof(time));
    std::copy_n(reinterpret_cast<uint8_t *>(&time),
            sizeof(time),
            time_bytes.begin());

    std::vector<uint8_t> output(num_bytes);

    while (num_bytes > 0) {
        std::vector<uint8_t> hmac = hmac_sha256(seed, time_bytes);
        size_t copy_bytes = std::min(num_bytes, hmac.size());
        std::copy(hmac.begin(),
                hmac.begin() + copy_bytes,
                output.end() - num_bytes);

        time_bytes[sizeof(time) - 1]++;
        num_bytes -= copy_bytes;
    }

    return output;
}

std::string algorithm_to_string(AlgorithmType algorithm) {
    switch (algorithm) {
        case AlgorithmType::RFC6238:
            return "rfc6238";
        case AlgorithmType::HMAC_SHA256:
            return "hmac-sha256";
        default:
            std::unreachable();
    }
}

absl::StatusOr<std::vector<uint8_t>> decrypt_seed(
        TOTPConfig const &config, std::string_view password) {
    auto key = derive_key(password,
            config.salt,
            config.enc_seed.size(),
            config.scrypt_params);
    if (!key.ok())
        return key.status();

    std::vector<uint8_t> seed(config.enc_seed.size());
    for (size_t i = 0; i < seed.size(); ++i) {
        seed[i] = config.enc_seed[i] ^ (*key)[i % key->size()];
    }

    if (crc32(seed) != config.crc) {
        return absl::InternalError("CRC mismatch");
    }

    return seed;
}

template<typename T>
std::string to_hex(T value) {
    std::string bytes(reinterpret_cast<char *>(&value), sizeof(T));
    return absl::BytesToHexString(bytes);
}

template<typename T>
absl::StatusOr<T> from_hex(std::string_view hex) {
    std::string bytes;
    if (!absl::HexStringToBytes(hex, &bytes)) {
        return absl::InvalidArgumentError("Invalid hex string");
    }
    T result;
    std::copy(bytes.begin(), bytes.end(), reinterpret_cast<char *>(&result));
    return result;
}

absl::StatusOr<TOTPConfig> load_config(
        std::string const &filename, std::string const &profile_name) {
    toml::table table = toml::parse_file(filename);
    TOTPConfig config;

    auto profile_table = table[profile_name];
    if (!profile_table.is_table()) {
        LOG(ERROR) << "Profile [" << profile_name
                   << "] not found in config file";
        return absl::InvalidArgumentError("Profile not found");
    }

    config.name = profile_name;
    auto [seed, crc] = [&]() -> std::pair<std::vector<uint8_t>, uint64_t> {
        std::string seed_str =
                profile_table["seed"].value<std::string>().value_or("");
        auto colon_pos = seed_str.find(':');
        if (colon_pos == std::string::npos)
            return {{}, 0};
        std::string crc_str = seed_str.substr(colon_pos + 1);
        uint64_t crc;
        if (!absl::SimpleAtoi(crc_str, &crc))
            return {{}, 0};
        std::string seed_hex = seed_str.substr(0, colon_pos);
        std::string seed_bytes;
        if (!absl::HexStringToBytes(seed_hex, &seed_bytes))
            return {{}, 0};
        return {std::vector<uint8_t>(seed_bytes.begin(), seed_bytes.end()),
                crc};
    }();
    config.enc_seed = seed;
    config.crc = crc;

    std::string salt_hex =
            profile_table["salt"].value<std::string>().value_or("");
    std::string salt_bytes;
    if (absl::HexStringToBytes(salt_hex, &salt_bytes)) {
        config.salt =
                std::vector<uint8_t>(salt_bytes.begin(), salt_bytes.end());
    }

    std::string algo_str =
            profile_table["algorithm"].value<std::string>().value_or("");
    if (algo_str == "rfc6238") {
        config.algorithm = AlgorithmType::RFC6238;
    } else if (algo_str == "hmac-sha256") {
        config.algorithm = AlgorithmType::HMAC_SHA256;
    } else {
        return absl::InvalidArgumentError("Unknown algorithm");
    }

    if (!profile_table["scrypt_opslimit"].is_string()
            || !profile_table["scrypt_memlimit"].is_string()) {
        return absl::InvalidArgumentError("Invalid scrypt parameters");
    }

    absl::StatusOr<uint64_t> opslimit = from_hex<uint64_t>(
            profile_table["scrypt_opslimit"].value<std::string>().value());

    if (!opslimit.ok()) {
        return opslimit.status();
    }

    absl::StatusOr<uint64_t> memlimit = from_hex<uint64_t>(
            profile_table["scrypt_memlimit"].value<std::string>().value());

    if (!memlimit.ok()) {
        return memlimit.status();
    }

    config.scrypt_params = {opslimit.value(), memlimit.value()};

    std::string value =
            profile_table["interval"].value<std::string>().value_or("");
    if (!absl::ParseDuration(value, &config.interval)) {
        return absl::InvalidArgumentError("Invalid interval");
    }

    return config;
}

void write_config(TOTPConfig const &config, std::string const &filename) {
    if (!std::filesystem::exists(filename)) {
        std::ofstream file(filename);
        file << toml::table{};
    } else if (!std::filesystem::is_regular_file(filename)) {
        LOG(ERROR) << "Invalid file";
        return;
    }

    toml::table table = toml::parse_file(filename);

    toml::table profile_table;
    profile_table.insert_or_assign("seed",
            bytes_to_hex_string(config.enc_seed) + ":"
                    + std::to_string(config.crc));
    profile_table.insert_or_assign("salt", bytes_to_hex_string(config.salt));
    profile_table.insert_or_assign(
            "algorithm", algorithm_to_string(config.algorithm));
    profile_table.insert_or_assign(
            "interval", absl::FormatDuration(config.interval));
    profile_table.insert_or_assign(
            "scrypt_opslimit", to_hex(config.scrypt_params.opslimit));
    profile_table.insert_or_assign(
            "scrypt_memlimit", to_hex(config.scrypt_params.memlimit));

    if (auto existing = table[config.name]; existing.is_table()) {
        LOG(WARNING) << "Profile [" << config.name << "] already exists";
        std::cerr << "Overwrite? ";
        if (std::cin.get() != 'y') {
            LOG(INFO) << "Aborted...";
            return;
        }
    }

    LOG(INFO) << "To retrieve the seed again, use the following command:";
    LOG(INFO) << "totp -d " << config.name;

    table.insert_or_assign(config.name, profile_table);

    std::ofstream file(filename, std::ios::app);
    file << table;
}

#define ABSL_FLAG_ALIAS(type, alias_name, original_flag) \
    ABSL_FLAG(type, \
            alias_name, \
            absl::GetFlag(FLAGS_##original_flag), \
            "Alias for " #original_flag);

#define ALIAS_ABSL_FLAG(original_name, alias_name) \
    absl::SetFlag(&FLAGS_##original_name, absl::GetFlag(FLAGS_##alias_name));

ABSL_FLAG(bool, help, false, "Print help message");
ABSL_FLAG_ALIAS(bool, h, help);

ABSL_FLAG(std::string, decrypt, "", "Decrypt seed of profile");
ABSL_FLAG_ALIAS(std::string, d, decrypt);

ABSL_FLAG(bool, new, false, "Generate new seed");
ABSL_FLAG_ALIAS(bool, n, new);

ABSL_FLAG(uint32_t, generate, 8, "[num bytes] Generate TOTP with num bytes");
ABSL_FLAG_ALIAS(uint32_t, g, generate);

ABSL_FLAG(std::string, output, "config-otb.toml", "Output file");
ABSL_FLAG_ALIAS(std::string, o, output);

ABSL_FLAG(std::string, config, "config-otb.toml", "Configuration file path");
ABSL_FLAG_ALIAS(std::string, c, config);

ABSL_FLAG(std::string, profile, "", "Profile name");
ABSL_FLAG_ALIAS(std::string, p, profile);

ABSL_FLAG(std::string, format, "hex", "Output format");
ABSL_FLAG_ALIAS(std::string, f, format);

int main(int argc, char *argv[]) {
    absl::InitializeLog();
    absl::SetMinLogLevel(absl::LogSeverityAtLeast::kInfo);
    absl::SetStderrThreshold(absl::LogSeverity::kInfo);

    absl::SetProgramUsageMessage("arbitrary TOTP generator");
    absl::ParseCommandLine(argc, argv);

    ALIAS_ABSL_FLAG(help, h);
    ALIAS_ABSL_FLAG(decrypt, d);
    ALIAS_ABSL_FLAG(new, n);
    ALIAS_ABSL_FLAG(generate, g);
    ALIAS_ABSL_FLAG(output, o);
    ALIAS_ABSL_FLAG(config, c);
    ALIAS_ABSL_FLAG(profile, p);
    ALIAS_ABSL_FLAG(format, f);

    if (argc == 1 || absl::GetFlag(FLAGS_help)) {
        std::cout << absl::ProgramUsageMessage() << "\n\n";
        std::cout << "Usage: totp [options]\n"
                     "Options:\n"
                     "  -h, --help\t\tPrint this message\n"
                     "  -d, --decrypt\t\tDecrypt seed of profile\n"
                     "  -n, --new\t\tGenerate new seed\n"
                     "  -g, --generate\tGenerate TOTP with num bytes\n"
                     "  -o, --output\t\tOutput file\n"
                     "  -c, --config\t\tConfiguration file path\n"
                     "  -p, --profile\t\tProfile name\n"
                     "  -f, --format\t\tOutput format\n";
        return argc == 1 ? -1 : 0;
    }

    if (sodium_init() == -1) {
        LOG(ERROR) << "Failed to initialize Libsodium";
        return -1;
    }

    OutputFormat output_format;
    if (absl::GetFlag(FLAGS_format) == "hex") {
        output_format = OutputFormat::Hex;
    } else if (absl::GetFlag(FLAGS_format) == "base64") {
        output_format = OutputFormat::Base64;
    } else {
        LOG(ERROR) << "Invalid output format";
        return -1;
    }

    if (absl::GetFlag(FLAGS_decrypt) != "") {
        absl::StatusOr<TOTPConfig> config = load_config(
                absl::GetFlag(FLAGS_config), absl::GetFlag(FLAGS_decrypt));

        if (!config.ok()) {
            LOG(ERROR) << config.status();
            return -1;
        }

        std::optional<std::string> password = prompt_password();
        if (!password) {
            LOG(ERROR) << "Failed to get password";
            return -1;
        }

        auto seed = decrypt_seed(*config, *password);
        if (!seed.ok()) {
            LOG(ERROR) << seed.status();
            return -1;
        }

        std::cout << bytes_to_hex_string(*seed) << std::endl;

        sodium_memzero(password->data(), password->size());
        sodium_memzero(seed->data(), seed->size());

        return 0;
    }

    if (absl::GetFlag(FLAGS_new)) {
        auto config = build_config_interactive(output_format);
        if (!config.ok()) {
            LOG(ERROR) << config.status();
            return -1;
        }

        write_config(*config, absl::GetFlag(FLAGS_output));

        return 0;
    }

    if (absl::GetFlag(FLAGS_generate) > 0) {
        std::string profile_name = absl::GetFlag(FLAGS_profile);

        if (profile_name.empty()) {
            LOG(ERROR) << "Profile name is required";
            return -1;
        }

        absl::StatusOr<TOTPConfig> config =
                load_config(absl::GetFlag(FLAGS_config), profile_name);
        if (!config.ok()) {
            LOG(ERROR) << config.status();
            return -1;
        }

        std::optional<std::string> password = prompt_password();
        if (!password) {
            LOG(ERROR) << "Failed to get password";
            return -1;
        }

        auto seed = decrypt_seed(*config, *password);
        if (!seed.ok()) {
            LOG(ERROR) << seed.status();
            return -1;
        }

        std::vector<uint8_t> bytes = generate_totp_hmac_sha256(
                *seed, absl::GetFlag(FLAGS_generate), config->interval);

        print_bytes(bytes, output_format, std::cout);

        sodium_memzero(password->data(), password->size());
        sodium_memzero(seed->data(), seed->size());
    }

    return 0;
}
