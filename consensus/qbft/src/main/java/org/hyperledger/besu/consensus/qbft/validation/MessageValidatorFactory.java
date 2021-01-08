/*
 * Copyright 2020 ConsenSys AG.
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
package org.hyperledger.besu.consensus.qbft.validation;

import org.hyperledger.besu.consensus.common.bft.ConsensusRoundIdentifier;
import org.hyperledger.besu.ethereum.core.BlockHeader;

public class MessageValidatorFactory {

  @SuppressWarnings("UnusedVariables")
  public RoundChangeMessageValidator createRoundChangeMessageValidator(
      final long chainHeight, final BlockHeader parentHeader) {
    return new RoundChangeMessageValidator();
  }

  public MessageValidator createMessageValidator(
      final ConsensusRoundIdentifier roundIdentifier, final BlockHeader parentHeader) {
    return new MessageValidator();
  }

  public FutureRoundProposalMessageValidator createFutureRoundProposalMessageValidator(
      long chainHeight, BlockHeader parentHeader) {
    return new FutureRoundProposalMessageValidator();
  }
}
