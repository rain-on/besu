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
package org.hyperledger.besu.consensus.qbft.payload;

import org.hyperledger.besu.consensus.common.bft.ConsensusRoundIdentifier;
import org.hyperledger.besu.consensus.common.bft.payload.Payload;
import org.hyperledger.besu.consensus.qbft.QbftConsensusRoundIdentifier;
import org.hyperledger.besu.consensus.qbft.messagedata.QbftV1;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.rlp.RLPInput;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

import java.util.Objects;
import java.util.StringJoiner;

public class PreparePayload implements Payload {

  private static final int TYPE = QbftV1.PREPARE;
  private final QbftConsensusRoundIdentifier roundIdentifier;
  private final Hash digest;

  public PreparePayload(final QbftConsensusRoundIdentifier roundIdentifier, final Hash digest) {
    this.roundIdentifier = roundIdentifier;
    this.digest = digest;
  }

  public static PreparePayload readFrom(final RLPInput rlpInput) {
    rlpInput.enterList();
    final QbftConsensusRoundIdentifier roundIdentifier = QbftConsensusRoundIdentifier.readFrom(rlpInput);
    final Hash digest = Payload.readDigest(rlpInput);
    rlpInput.leaveList();
    return new PreparePayload(roundIdentifier, digest);
  }

  @Override
  public void writeTo(final RLPOutput rlpOutput) {
    rlpOutput.startList();
    roundIdentifier.writeTo(rlpOutput);
    rlpOutput.writeBytes(digest);
    rlpOutput.endList();
  }

  @Override
  public int getMessageType() {
    return TYPE;
  }

  public Hash getDigest() {
    return digest;
  }

  @Override
  public ConsensusRoundIdentifier getRoundIdentifier() {
    return roundIdentifier;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final PreparePayload that = (PreparePayload) o;
    return Objects.equals(roundIdentifier, that.roundIdentifier)
        && Objects.equals(digest, that.digest);
  }

  @Override
  public int hashCode() {
    return Objects.hash(roundIdentifier, digest);
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", PreparePayload.class.getSimpleName() + "[", "]")
        .add("roundIdentifier=" + roundIdentifier)
        .add("digest=" + digest)
        .toString();
  }
}
