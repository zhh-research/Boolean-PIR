#pragma once
#include "SPIRIT/pir/batch_protocol.h"
#include <memory>

namespace spirit::pir {
void PrepareBatchQuery(const BatchPublicParams&, const seal::SEALContext&, seal::KeyGenerator&,
                       seal::Encryptor&, seal::Evaluator&, BatchQueryMessage&, BatchClientState&);
void BindBatchQuery(const BatchPublicParams&, const std::vector<std::size_t>&, BatchQueryMessage&,
                    BatchClientState&);
void AnswerWithoutSecret(const BatchPublicParams&, const BatchServerState&,
                         const BatchAnswerPrecompState&, BatchQueryAnswerPrecompState&,
                         BatchQueryMessage&, const seal::SEALContext&, seal::Evaluator&,
                         BatchResponseMessage&);
void BatchExtractParallel(const BatchPublicParams&, const BatchClientState&,
                          const BatchResponseMessage&, const seal::SEALContext&,
                          const std::vector<std::unique_ptr<seal::Decryptor>>&,
                          std::vector<std::vector<std::uint8_t>>&);
}
