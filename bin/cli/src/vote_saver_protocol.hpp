//---------------------------------------------------------------------------//
// Copyright (c) 2018-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Noam Y <@NoamDev>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#include <boost/assert.hpp>

#include <iostream>
#include <fstream>
#include <string>
#include <functional>
#include <ctime>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <nil/crypto3/zk/components/voting/encrypted_input_voting.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/disjunction.hpp>

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <nil/crypto3/zk/algorithms/generate.hpp>
#include <nil/crypto3/zk/algorithms/verify.hpp>
#include <nil/crypto3/zk/algorithms/prove.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/primary_input.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/proof.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/verification_key.hpp>
#include <nil/crypto3/marshalling/zk/types/r1cs_gg_ppzksnark/fast_proving_key.hpp>
#include <nil/crypto3/marshalling/pubkey/types/elgamal_verifiable.hpp>

#include <nil/crypto3/pubkey/algorithm/generate_keypair.hpp>
#include <nil/crypto3/pubkey/algorithm/encrypt.hpp>
#include <nil/crypto3/pubkey/algorithm/decrypt.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_encryption.hpp>
#include <nil/crypto3/pubkey/algorithm/verify_decryption.hpp>
#include <nil/crypto3/pubkey/algorithm/rerandomize.hpp>
#include <nil/crypto3/pubkey/elgamal_verifiable.hpp>
#include <nil/crypto3/pubkey/modes/verifiable_encryption.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/detail/pack.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::pubkey;
using namespace nil::crypto3::marshalling;
using namespace nil::crypto3::zk;


#define DISABLE_OUTPUT

template<typename ...Args>
inline void log(Args && ...args)
{
#ifndef DISABLE_OUTPUT
    (std::cout<< ... << args);
#endif
}

template<typename ...Args>
inline void logln(Args && ...args)
{
#ifndef DISABLE_OUTPUT
    (std::cout << ... << args) << std::endl;
#endif
}

struct encrypted_input_policy {
    using pairing_curve_type = curves::bls12_381;
    using curve_type = curves::jubjub;
    using base_points_generator_hash_type = hashes::sha2<256>;
    using hash_params = hashes::find_group_hash_default_params;
    using hash_component = components::pedersen<curve_type, base_points_generator_hash_type, hash_params>;
    using hash_type = typename hash_component::hash_type;
    using merkle_hash_component = hash_component;
    using merkle_hash_type = typename merkle_hash_component::hash_type;
    using field_type = typename hash_component::field_type;
    static constexpr std::size_t arity = 2;
    using voting_component =
    components::encrypted_input_voting<arity, hash_component, merkle_hash_component, field_type>;
    using merkle_proof_component = typename voting_component::merkle_proof_component;
    using encryption_scheme_type = elgamal_verifiable<pairing_curve_type>;
    using proof_system = typename encryption_scheme_type::proof_system_type;
    static constexpr std::size_t msg_size = 25;
    static constexpr std::size_t secret_key_bits = hash_type::digest_bits;
    static constexpr std::size_t public_key_bits = secret_key_bits;
};

encrypted_input_policy::proof_system::constraint_system_type vote_saver_protocol_circuit(std::size_t tree_depth,  std::size_t eid_bits) {
    using scalar_field_value_type = typename encrypted_input_policy::pairing_curve_type::scalar_field_type::value_type;

    logln("Voting system administrator generates R1CS..." );
    components::blueprint<encrypted_input_policy::field_type> bp;
    components::block_variable<encrypted_input_policy::field_type> m_block(bp, encrypted_input_policy::msg_size);

    std::size_t chunk_size = encrypted_input_policy::field_type::value_bits - 1;

    components::blueprint_variable_vector<encrypted_input_policy::field_type> eid_packed;
    std::size_t eid_packed_size = (eid_bits + (chunk_size - 1)) / chunk_size;
    eid_packed.allocate(bp, eid_packed_size);

    components::blueprint_variable_vector<encrypted_input_policy::field_type> sn_packed;
    std::size_t sn_packed_size = (encrypted_input_policy::hash_component::digest_bits + (chunk_size - 1)) / chunk_size;
    sn_packed.allocate(bp, sn_packed_size);

    components::blueprint_variable_vector<encrypted_input_policy::field_type> root_packed;
    std::size_t root_packed_size = (encrypted_input_policy::hash_component::digest_bits + (chunk_size - 1)) / chunk_size;
    root_packed.allocate(bp, root_packed_size);

    std::size_t primary_input_size = bp.num_variables();

    components::block_variable<encrypted_input_policy::field_type> eid_block(bp, eid_bits);
    components::digest_variable<encrypted_input_policy::field_type> sn_digest(
            bp, encrypted_input_policy::hash_component::digest_bits);
    components::digest_variable<encrypted_input_policy::field_type> root_digest(
            bp, encrypted_input_policy::merkle_hash_component::digest_bits);
    logln("Variables number in the generated R1CS: " , bp.num_variables() );

    components::multipacking_component<encrypted_input_policy::field_type> eid_packer(bp, eid_block.bits, eid_packed, chunk_size);
    components::multipacking_component<encrypted_input_policy::field_type> sn_packer(bp, sn_digest.bits, sn_packed, chunk_size);
    components::multipacking_component<encrypted_input_policy::field_type> root_packer(bp, root_digest.bits, root_packed, chunk_size);
    logln("Variables number in the generated R1CS: " , bp.num_variables() );

    components::blueprint_variable_vector<encrypted_input_policy::field_type> address_bits_va;
    address_bits_va.allocate(bp, tree_depth);
    encrypted_input_policy::merkle_proof_component path_var(bp, tree_depth);
    components::block_variable<encrypted_input_policy::field_type> sk_block(bp,
                                                                            encrypted_input_policy::secret_key_bits);
    logln("Variables number in the generated R1CS: " , bp.num_variables() );
    encrypted_input_policy::voting_component vote_var(
            bp, m_block, eid_block, sn_digest, root_digest, address_bits_va, path_var, sk_block,
            components::blueprint_variable<encrypted_input_policy::field_type>(0));
    logln("Variables number in the generated R1CS: " , bp.num_variables() );

    eid_packer.generate_r1cs_constraints(true);
    sn_packer.generate_r1cs_constraints(true);
    root_packer.generate_r1cs_constraints(true);

    path_var.generate_r1cs_constraints();
    vote_var.generate_r1cs_constraints();
    logln("R1CS generation finished." );
    logln("Constraints number in the generated R1CS: " , bp.num_constraints() );
    logln("Variables number in the generated R1CS: " , bp.num_variables() );
    bp.set_input_sizes(primary_input_size);

    return bp.get_constraint_system();
}