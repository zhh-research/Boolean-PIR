import argparse
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("upstream", type=Path)
p.add_argument("output", type=Path)
a = p.parse_args()
source = a.upstream / "src/SPIRIT/pir/batch_protocol.cpp"
text = source.read_text()
a.output.parent.mkdir(parents=True, exist_ok=True)


def once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError(f"Unexpected SPIRIT source: {old[:60]}")
    return text.replace(old, new, 1)


text = (
    '#include <exception>\n#include <omp.h>\n#include <sodium.h>\n#include "spirit_overlay.hpp"\n'
    + text
)
first = text.index("        void sample_ternary_secret(")
last = text.index("        void sample_query_noise(", first)
text = (
    text[:first]
    + """        void sample_ternary_secret(size_t dimension, std::vector<int64_t> &secret)
        {
            secret.resize(dimension);
            for (auto &value : secret)
                value = static_cast<int64_t>(randombytes_uniform(3)) - 1;
        }

"""
    + text[last:]
)

lo = text.index("    void BatchQuery(")
hi = text.index("    void BatchAnswerPrecompute(", lo)
query = text[lo:hi]
ready = query.index("        sample_ternary_secret(")
loop = query.index("        const size_t num_buckets")
use = query.index("        std::random_device", loop)
mid = query.index("            const auto &bucket_public_params", use)
template = query[ready:loop]
schedule = query[use:mid]
replacement = (
    """    void PrepareBatchQuery(
        const BatchPublicParams &public_params, const SEALContext &context,
        KeyGenerator &keygen, Encryptor &encryptor, Evaluator &evaluator,
        BatchQueryMessage &query, BatchClientState &client_state)
    {
        validate_batch_public_params(public_params);
        if (context.first_context_data()->parms().poly_modulus_degree() < public_params.params.lwe_dimension)
            throw std::invalid_argument("context poly modulus degree must be at least lwe_dimension");
        query = {};
        client_state = {};
"""
    + template
    + """        const size_t num_buckets = public_params.pbc_public_params.num_buckets;
        query.bucket_queries.resize(num_buckets);
        for (size_t b = 0; b < num_buckets; ++b)
        {
            auto &bucket = query.bucket_queries[b];
            bucket.bucket_index = b;
            const auto &pp = public_params.bucket_public_params[b];
            build_query_vector_from_seed(
                pp.public_matrix_seed, pp.params.cols, pp.params.lwe_dimension,
                client_state.query_secret, 0, pp.params.record_plain_modulus, bucket.query_vector);
            bucket.query_vector[0] -= static_cast<uint32_t>(round_div_u64(1ULL << 32, pp.params.record_plain_modulus));
        }
    }

    void BindBatchQuery(
        const BatchPublicParams &public_params, const std::vector<size_t> &batch_indices,
        BatchQueryMessage &query, BatchClientState &client_state)
    {
        client_state.batch_indices = batch_indices;
        AssignBatchIndicesToBuckets(public_params.pbc_public_params, batch_indices, client_state.query_plan);
        const size_t num_buckets = public_params.pbc_public_params.num_buckets;
"""
    + schedule.replace(
        "            BatchBucketQuery bucket_query;\n            bucket_query.bucket_index = bucket_index;\n\n",
        "",
    )
    + """
            const auto p = public_params.params.record_plain_modulus;
            query.bucket_queries[bucket_index].query_vector[target_col] +=
                static_cast<uint32_t>(round_div_u64(1ULL << 32, p));
        }
    }

"""
)

text = text[:lo] + replacement + text[hi:]

text = once(
    text,
    "        Encryptor &encryptor,\n        Evaluator &evaluator,\n        Decryptor &decryptor,\n        BatchResponseMessage &response)",
    "        Evaluator &evaluator,\n        BatchResponseMessage &response)",
)
text = once(text, "    void BatchAnswer(\n", "    void AnswerWithoutSecret(\n")
text = once(text, "        (void)encryptor;\n        (void)decryptor;\n", "")


parallel = """        template<class Work>
        void for_each_bucket(size_t count, Work work, int threads = omp_get_max_threads())
        {
            std::exception_ptr failure;
            #pragma omp parallel for schedule(dynamic, 1) num_threads(threads)
            for (int64_t i = 0; i < static_cast<int64_t>(count); ++i)
            {
                try { work(static_cast<size_t>(i)); }
                catch (...)
                {
                    #pragma omp critical(retrieval_spirit_error)
                    {
                        if (!failure) failure = std::current_exception();
                    }
                }
            }
            if (failure) std::rethrow_exception(failure);
        }

"""
text = once(
    text,
    "        constexpr uint64_t lwe_modulus_value",
    parallel + "        constexpr uint64_t lwe_modulus_value",
)


def parallel_section(source, begin, end, old_loop, new_loop, replacements=()):
    a = source.index(begin)
    b = source.index(end, a + len(begin))
    section = source[a:b]
    for before, after in replacements:
        section = once(section, before, after)
    section = once(section, old_loop, new_loop)
    close = section.rindex("        }\n", 0, section.rindex("    }\n"))
    section = section[:close] + "        });\n" + section[close + 10 :]
    return source[:a] + section + source[b:]


serial_loop = "        for (size_t bucket_index = 0; bucket_index < num_buckets; bucket_index++)\n        {"
worker_loop = "        for_each_bucket(num_buckets, [&](size_t bucket_index)\n        {"
for begin, end in (
    ("    void BatchDBSetup(", "    void PrepareBatchQuery("),
    ("    void BatchAnswerPrecompute(", "    void BatchAnswerQueryPrecompute("),
):
    text = parallel_section(text, begin, end, serial_loop, worker_loop)
text = parallel_section(
    text,
    "    void PrepareBatchQuery(",
    "    void BindBatchQuery(",
    "        for (size_t b = 0; b < num_buckets; ++b)\n        {",
    "        for_each_bucket(num_buckets, [&](size_t b)\n        {",
)

serial_query_loop = (
    "        for (const auto &bucket_query : query.bucket_queries)\n        {"
)
worker_query_loop = (
    "        for_each_bucket(query.bucket_queries.size(), [&](size_t i)\n        {\n"
    "            const auto &bucket_query = query.bucket_queries[i];\n"
    "            Evaluator bucket_evaluator(context);"
)
text = parallel_section(
    text,
    "    void BatchAnswerQueryPrecompute(",
    "    void AnswerWithoutSecret(",
    serial_query_loop,
    worker_query_loop,
    [
        (
            "                evaluator,\n                bucket_precomp_state.packed_c1_chunks);",
            "                bucket_evaluator,\n                bucket_precomp_state.packed_c1_chunks);",
        )
    ],
)

answer_start = text.index("    void AnswerWithoutSecret(")
answer_end = text.index("    void BatchExtract(", answer_start)
answer = text[answer_start:answer_end]
answer = answer[: answer.index("        double total_ms =")] + "    }\n\n"
answer = "\n".join(
    line
    for line in answer.split("\n")
    if not any(
        key in line
        for key in (
            "step_start =",
            "total_start =",
            "using clock =",
            "ms +=",
            "double matvec_ms",
            "double modswitch_ms",
            "double b_extract_ms",
            "double lwe_pack_ms",
            "double secret_unpack_online_ms",
            "clock::now() - step_start",
        )
    )
)
answer = once(
    answer,
    "context, evaluator, b_chunks, false",
    "context, bucket_evaluator, b_chunks, false",
)
answer = once(
    answer,
    "                evaluator,\n                bucket_response.packed_columns);",
    "                bucket_evaluator,\n                bucket_response.packed_columns);",
)
text = text[:answer_start] + answer + text[answer_end:]
text = parallel_section(
    text,
    "    void AnswerWithoutSecret(",
    "    void BatchExtract(",
    serial_query_loop,
    worker_query_loop,
)

text = once(
    text,
    "                    decryptor.decrypt(bucket_response.packed_columns[chunk_index], bucket_plaintexts[chunk_index]);",
    """                    auto &plain = bucket_plaintexts[chunk_index];
                    decryptor.decrypt(bucket_response.packed_columns[chunk_index], plain);
                    if (plain.coeff_count() < poly_modulus_degree)
                        plain.resize(poly_modulus_degree);""",
)


end = text.rindex("}")
serial = text[text.index("    void BatchExtract(") : end]
parallel_extract = once(serial, "void BatchExtract(", "void BatchExtractParallel(")
parallel_extract = once(
    parallel_extract,
    "        Decryptor &decryptor,",
    "        const std::vector<std::unique_ptr<Decryptor>> &workers,",
)
parallel_extract = once(
    parallel_extract,
    """        std::vector<std::vector<Plaintext>> decrypted_bucket_chunks(response.bucket_responses.size());
        std::vector<std::vector<uint8_t>> chunk_loaded(response.bucket_responses.size());

        for (const auto &assignment : client_state.query_plan.assignments)
        {""",
    """        for_each_bucket(client_state.query_plan.assignments.size(), [&](size_t i)
        {
            auto &decryptor = *workers.at(omp_get_thread_num());
            const auto &assignment = client_state.query_plan.assignments[i];""",
)
parallel_extract = once(
    parallel_extract,
    """            auto &bucket_plaintexts = decrypted_bucket_chunks[bucket_index];
            auto &bucket_chunk_loaded = chunk_loaded[bucket_index];

            if (bucket_plaintexts.empty())
            {
                bucket_plaintexts.resize(bucket_response.packed_columns.size());
                bucket_chunk_loaded.assign(bucket_response.packed_columns.size(), 0);
            }""",
    """            std::vector<Plaintext> bucket_plaintexts(bucket_response.packed_columns.size());
            std::vector<uint8_t> bucket_chunk_loaded(bucket_response.packed_columns.size(), 0);""",
)
close = parallel_extract.rindex("        }\n")
parallel_extract = (
    parallel_extract[:close]
    + "        }, static_cast<int>(workers.size()));\n"
    + parallel_extract[close + 10 :]
)
text = text[:end] + parallel_extract + text[end:]
a.output.write_text(text)
