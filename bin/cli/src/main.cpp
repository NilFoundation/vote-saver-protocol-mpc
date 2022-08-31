#include <iostream>
#include <fstream>
#include <string>
#include <functional>
#include <filesystem>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>

#include <nil/crypto3/zk/commitments/polynomial/powers_of_tau.hpp>
#include <nil/crypto3/zk/commitments/polynomial/r1cs_gg_ppzksnark_mpc.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/powers_of_tau/result.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/r1cs_gg_ppzksnark_mpc/public_key.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/fast_proving_key.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/verification_key.hpp>

#include "vote_saver_protocol.hpp"

using namespace nil::crypto3;

using curve_type = algebra::curves::bls12<381>;
using scheme_type = zk::commitments::r1cs_gg_ppzksnark_mpc<curve_type>;
using pot_result_type = zk::commitments::detail::powers_of_tau_result<curve_type>;
using private_key_type = scheme_type::private_key_type;
using public_key_type = scheme_type::public_key_type;
using crs_type = scheme_type::proving_scheme_keypair_type;
using constraint_system_type = scheme_type::constraint_system_type;

namespace po = boost::program_options;

struct marshalling_policy {
    using endianness = nil::marshalling::option::little_endian;
    using field_base_type = nil::marshalling::field_type<endianness>;
    using pot_result_marshalling_type = marshalling::types::powers_of_tau_result<field_base_type, pot_result_type>;
    using proof_system_proving_key_marshalling_type = marshalling::types::r1cs_gg_ppzksnark_fast_proving_key<field_base_type, crs_type::first_type>;
    using proof_system_verification_key_marshalling_type = marshalling::types::r1cs_gg_ppzksnark_verification_key<field_base_type, crs_type::second_type>;
    using public_key_marshalling_type = marshalling::types::r1cs_gg_ppzksnark_mpc_public_key<field_base_type, public_key_type>;

    template<typename MarshalingType, typename InputObj, typename F>
    static std::vector<std::uint8_t> serialize_obj(const InputObj &in_obj, const std::function<F> &f) {
        MarshalingType filled_val = f(in_obj);
        std::vector<std::uint8_t> blob(filled_val.length());
        auto it = std::begin(blob);
        nil::marshalling::status_type status = filled_val.write(it, blob.size());
        BOOST_ASSERT(status == nil::marshalling::status_type::success);
        return blob;
    }

    template<typename MarshalingType, typename ReturnType, typename InputBlob, typename F>
    static ReturnType deserialize_obj(const InputBlob &blob, const std::function<F> &f) {
        MarshalingType marshaling_obj;
        auto it = std::cbegin(blob);
        nil::marshalling::status_type status = marshaling_obj.read(it, blob.size());
        BOOST_ASSERT(status == nil::marshalling::status_type::success);
        return f(marshaling_obj);
    }

    static pot_result_type deserialize_pot_result(const std::vector<std::uint8_t>& blob) {
        return deserialize_obj<pot_result_marshalling_type, pot_result_type>(blob,
            std::function(nil::crypto3::marshalling::types::make_powers_of_tau_result<pot_result_type, endianness>));
    }

    static std::vector<std::uint8_t> serialize_crs(const crs_type& crs) {
        proof_system_proving_key_marshalling_type filled_pkey =
            nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_fast_proving_key<crs_type::first_type, endianness>(crs.first);
        proof_system_verification_key_marshalling_type filled_vkey =
            nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_verification_key<crs_type::second_type, endianness>(crs.second);

        std::vector<std::uint8_t> blob(filled_pkey.length() + filled_vkey.length());
        auto it = std::begin(blob);
        nil::marshalling::status_type status = filled_pkey.write(it, blob.size());
        BOOST_ASSERT(status == nil::marshalling::status_type::success);
        status = filled_vkey.write(it, blob.size() - filled_pkey.length());
        BOOST_ASSERT(status == nil::marshalling::status_type::success);
        return blob;
    }

    // static crs_type deserialize_crs(std::vector<std::uint8_t> blob) {
    //     proof_system_proving_key_marshalling_type pkey_marsh;
    //     auto it = std::cbegin(blob);
    //     nil::marshalling::status_type status = pkey_marsh.read(it, blob.size());
    //     BOOST_ASSERT(status == nil::marshalling::status_type::success);
    //     crs_type::first_type pkey  = nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_fast_proving_key<crs_type::first_type, endianness>(pkey_marsh);

    //     proof_system_verification_key_marshalling_type vkey_marsh;
    //     status = vkey_marsh.read(it, blob.size() - pkey_marsh.length());
    //     BOOST_ASSERT(status == nil::marshalling::status_type::success);
    //     crs_type::second_type vkey  = nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_verification_key<crs_type::second_type, endianness>(vkey_marsh);

    //     return {pkey, vkey};
    // }

    static public_key_type deserialize_public_key(const std::vector<std::uint8_t>& blob) {
        return deserialize_obj<public_key_marshalling_type, public_key_type>(blob,
            std::function(nil::crypto3::marshalling::types::make_r1cs_gg_ppzksnark_mpc_public_key<public_key_type, endianness>));
    }

    template<typename Path, typename Blob>
    static bool write_obj(const Path &path, std::initializer_list<Blob> blobs) {
        if (std::filesystem::exists(path)) {
            std::cout << "File " << path << " exists and won't be overwritten." << std::endl;
            return false;
        }
        std::ofstream out(path, std::ios_base::binary);
        for (const auto &blob : blobs) {
            for (const auto b : blob) {
                out << b;
            }
        }
        out.close();
        return true;
    }

    template<typename Path>
    static std::vector<std::uint8_t> read_obj(const Path &path) {
        BOOST_ASSERT_MSG(
                std::filesystem::exists(path),
                (std::string("File ") + path + std::string(" doesn't exist, make sure you created it!")).c_str());
        std::ifstream in(path, std::ios_base::binary);
        std::stringstream buffer;
        buffer << in.rdbuf();
        auto blob_str = buffer.str();
        return {std::cbegin(blob_str), std::cend(blob_str)};
    }

};

std::size_t calculate_m(std::size_t tree_depth) {
    constraint_system_type cs = vote_saver_protocol_circuit(tree_depth, 64);
    std::size_t min_m = cs.num_constraints() + cs.num_inputs() + 1;
    return math::make_evaluation_domain<curve_type::scalar_field_type>(min_m)->m;
}

crs_type init_ceremony(std::size_t tree_depth, pot_result_type pot_result) {
    constraint_system_type cs = vote_saver_protocol_circuit(tree_depth, 64);
    return zk::commitments::detail::make_r1cs_gg_ppzksnark_keypair_from_powers_of_tau(cs, pot_result);
}

public_key_type contribute_randomness(crs_type &crs, boost::optional<public_key_type> &previous_public_key) {
    private_key_type private_key = scheme_type::generate_private_key();
    auto public_key = scheme_type::proof_eval(private_key, previous_public_key, crs);
    zk::commitments::detail::transform_keypair(crs, private_key);
    return public_key;
}

int main(int argc, char *argv[]) {
    std::string description =
        "A Trusted Setup Multi Party Computation Protcol for Vote Saver Protocol\n"
        "Usage:\n"
        "radix-m - Calculate the Radix Evaluation domain size required\n"
        "init - Initialize a trusted setup MPC ceremony\n"
        "contribute - Contribute randomness to the trusted setup\n"
        "verify - Verify all contributions\n"
        "Run `cli subcommand --help` for details about a specific subcommand";
    
    int usage_error_exit_code = 1;
    int help_message_exit_code = 2;
    int invalid_exit_code = 3;
    int file_exists_exit_code = 4;
    
    if(argc < 2) {
        std::cout << description << std::endl;
        return help_message_exit_code;
    }

    std::string command = argv[1];
    if(command == "radix-m") {
        po::options_description desc("radix-m - Calculate the Radix Evaluation domain size required");
        desc.add_options()("help,h", "Display help message")
        ("tree-depth,d", po::value<std::size_t>(), "Voters merkle tree depth");

        po::variables_map vm;
        po::store(po::parse_command_line(argc-1, argv+1, desc), vm);
        po::notify(vm);

        if(argc < 3 || vm.count("help")) {
            std::cout << desc << std::endl;
            return help_message_exit_code;
        }

        if(!vm.count("tree-depth")) {
            std::cout << "missing argument -d [ --tree-depth ]" << std::endl;
            std::cout << desc << std::endl;
            return usage_error_exit_code;
        }

        std::size_t tree_depth = vm["tree-depth"].as<std::size_t>();
        std::cout << calculate_m(tree_depth) << std::endl;

    } else if(command == "init") {
        po::options_description desc("init - Initialize a trusted setup MPC ceremony");
        desc.add_options()("help,h", "Display help message")
        ("tree-depth,d", po::value<std::size_t>(), "Voters merkle tree depth")
        ("radix,r", po::value<std::string>(), "Radix Evalutation Domain path")
        ("output,o", po::value<std::string>(), "Initial challenge output path");

        po::variables_map vm;
        po::store(po::parse_command_line(argc-1, argv+1, desc), vm);
        po::notify(vm);

        if(argc < 3 || vm.count("help")) {
            std::cout << desc << std::endl;
            return help_message_exit_code;
        }

        if(!vm.count("tree-depth")) {
            std::cout << "missing argument -d [ --tree-depth ]" << std::endl;
            std::cout << desc << std::endl;
            return usage_error_exit_code;
        }

        if(!vm.count("radix")) {
            std::cout << "missing argument -r [ --radix ]" << std::endl;
            std::cout << desc << std::endl;
            return usage_error_exit_code;
        }

        if(!vm.count("output")) {
            std::cout << "missing argument -o [ --output ]" << std::endl;
            std::cout << desc << std::endl;
            return usage_error_exit_code;
        }
        
        std::size_t tree_depth = vm["tree-depth"].as<std::size_t>();
        std::string radix_path = vm["radix"].as<std::string>();
        std::string output_path = vm["output"].as<std::string>();

        std::cout << "Reading Radix from " << radix_path << std::endl;

        std::vector<std::uint8_t> radix_blob = marshalling_policy::read_obj(radix_path);
        pot_result_type pot_result = marshalling_policy::deserialize_pot_result(radix_blob);

        std::cout << "Initializing a challenge..." << std::endl;

        crs_type crs = init_ceremony(tree_depth, pot_result);

        std::cout << "Writing to file..." << std::endl;

        std::vector<std::uint8_t> crs_blob = marshalling_policy::serialize_crs(crs);
        if(!marshalling_policy::write_obj(output_path, {crs_blob})) {
            return file_exists_exit_code;
        }
        std::cout << "Challenge written to " << output_path << std::endl;
    // } else if(command == "contribute") {
    //     po::options_description desc("contribute - Contribute randomness to the trusted setup");
    //     desc.add_options()("help,h", "Display help message")
    //     ("challenge,c", po::value<std::string>(), "challenge input path")
    //     ("challenge-pubkey", po::value<std::string>(), "challenge public key path")
    //     ("output,o", po::value<std::string>(), "Response output path")
    //     ("pubkey-output", po::value<std::string>(), "Public key output path");

    //     po::variables_map vm;
    //     po::store(po::parse_command_line(argc-1, argv+1, desc), vm);
    //     po::notify(vm);

    //     if(argc < 3 || vm.count("help")) {
    //         std::cout << desc << std::endl;
    //         return help_message_exit_code;
    //     }

    //     if(!vm.count("challenge")) {
    //         std::cout << "missing argument -c [ --challenge ]" << std::endl;
    //         std::cout << desc << std::endl;
    //         return usage_error_exit_code;
    //     }

    //     if(!vm.count("challenge-pubkey")) {
    //         std::cout << "missing argument --challenge-pubkey" << std::endl;
    //         std::cout << desc << std::endl;
    //         return usage_error_exit_code;
    //     }

    //     if(!vm.count("output")) {
    //         std::cout << "missing argument -o [ --output ]" << std::endl;
    //         std::cout << desc << std::endl;
    //         return usage_error_exit_code;
    //     }

    //     if(!vm.count("pubkey-output")) {
    //         std::cout << "missing argument -p [ --public-key-output ]" << std::endl;
    //         std::cout << desc << std::endl;
    //         return usage_error_exit_code;
    //     }
        
    //     std::string challenge_path = vm["challenge"].as<std::string>();
    //     std::string challenge_pubkey_path = vm["challenge-pubkey"].as<std::string>();
    //     std::string output_path = vm["output"].as<std::string>();
    //     std::string pubkey_output_path = vm["pubkey-output"].as<std::string>();
        
    //     std::cout << "Reading challenge file: " << challenge_path << std::endl;
        
    //     std::vector<std::uint8_t> challenge_blob = marshalling_policy::read_obj(challenge_path);
    //     crs_type crs = marshalling_policy::deserialize_crs(challenge_blob);

    //     std::cout << "Reading challenge pub key file: " << challenge_pubkey_path << std::endl;

    //     std::vector<std::uint8_t> challenge_pubkey_blob = marshalling_policy::read_obj(challenge_pubkey_path);
    //     public_key_type challenge_pubkey = marshalling_policy::deserialize_public_key(challenge_pubkey_blob);

    //     std::cout << "Contributing randomness..." << std::endl;

    //     public_key_type public_key = contribute_randomness(crs, challenge_pubkey);
    } else {
        std::cout << "invalid command: " << command << std::endl;
        std::cout << description << std::endl;
        return usage_error_exit_code;
    }

    return 0;
}