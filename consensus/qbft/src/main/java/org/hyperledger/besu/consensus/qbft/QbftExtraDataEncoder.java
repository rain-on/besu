/*
 * Copyright ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.consensus.qbft;

import org.hyperledger.besu.consensus.common.bft.BftExtraData;
import org.hyperledger.besu.consensus.common.bft.BftExtraDataEncoder;
import org.hyperledger.besu.consensus.common.bft.Vote;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

/**
 * Represents the data structure stored in the extraData field of the BlockHeader used when
 * operating under an BFT consensus mechanism.
 */
public class QbftExtraDataEncoder implements BftExtraDataEncoder {
  private static final Logger LOG = LogManager.getLogger();

  public static Bytes encodeFromAddresses(final Collection<Address> addresses) {
    return new QbftExtraDataEncoder()
        .encode(
            new BftExtraData(
                Bytes.wrap(new byte[EXTRA_VANITY_LENGTH]),
                Collections.emptyList(),
                Optional.empty(),
                0,
                addresses));
  }

  public static String createGenesisExtraDataString(final List<Address> validators) {
    return encodeFromAddresses(validators).toString();
  }

  @Override
  public BftExtraData decode(final BlockHeader blockHeader) {
    final Object inputExtraData = blockHeader.getParsedExtraData();
    if (inputExtraData instanceof BftExtraData) {
      return (BftExtraData) inputExtraData;
    }
    LOG.warn(
        "Expected a BftExtraData instance but got {}. Reparsing required.",
        inputExtraData != null ? inputExtraData.getClass().getName() : "null");
    return decodeRaw(blockHeader.getExtraData());
  }

  @Override
  public BftExtraData decodeRaw(final Bytes input) {
    if (input.isEmpty()) {
      throw new IllegalArgumentException("Invalid Bytes supplied - Bft Extra Data required.");
    }

    final RLPInput rlpInput = new BytesValueRLPInput(input, false);

    rlpInput.enterList(); // This accounts for the "root node" which contains BFT data items.
    final Bytes vanityData = rlpInput.readBytes();
    final List<Address> validators = rlpInput.readList(Address::readFrom);

    final List<Vote> votes = rlpInput.readList(Vote::readFrom);
    final Optional<Vote> vote = votes.isEmpty() ? Optional.empty() : Optional.of(votes.get(0));

    final int round = rlpInput.readIntScalar();
    final List<SECPSignature> seals =
        rlpInput.readList(
            rlp -> SignatureAlgorithmFactory.getInstance().decodeSignature(rlp.readBytes()));
    rlpInput.leaveList();

    return new BftExtraData(vanityData, seals, vote, round, validators);
  }

  @Override
  public Bytes encode(final BftExtraData bftExtraData) {
    return encode(bftExtraData, EncodingType.ALL);
  }

  @Override
  public Bytes encodeWithoutCommitSeals(final BftExtraData bftExtraData) {
    return encode(bftExtraData, EncodingType.EXCLUDE_COMMIT_SEALS);
  }

  @Override
  public Bytes encodeWithoutCommitSealsAndRoundNumber(final BftExtraData bftExtraData) {
    return encode(bftExtraData, EncodingType.EXCLUDE_COMMIT_SEALS_AND_ROUND_NUMBER);
  }

  private Bytes encode(final BftExtraData bftExtraData, final EncodingType encodingType) {
    final BytesValueRLPOutput encoder = new BytesValueRLPOutput();
    encoder.startList();
    encoder.writeBytes(bftExtraData.getVanityData());
    encoder.writeList(bftExtraData.getValidators(), (validator, rlp) -> rlp.writeBytes(validator));

    final List<Vote> vote = bftExtraData.getVote().stream().collect(Collectors.toList());
    encoder.writeList(vote, Vote::writeTo);

    if (encodingType != EncodingType.EXCLUDE_COMMIT_SEALS_AND_ROUND_NUMBER) {
      encoder.writeIntScalar(bftExtraData.getRound());
      if (encodingType != EncodingType.EXCLUDE_COMMIT_SEALS) {
        encoder.writeList(
            bftExtraData.getSeals(), (committer, rlp) -> rlp.writeBytes(committer.encodedBytes()));
      }
    }
    encoder.endList();

    return encoder.encoded();
  }

  private enum EncodingType {
    ALL,
    EXCLUDE_COMMIT_SEALS,
    EXCLUDE_COMMIT_SEALS_AND_ROUND_NUMBER
  }
}
