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
package org.hyperledger.besu.tests.acceptance.ibft2;

import org.hyperledger.besu.tests.acceptance.dsl.AcceptanceTestBase;
import org.hyperledger.besu.tests.acceptance.dsl.node.BesuNode;

import java.io.IOException;

import org.junit.Test;

public class Ibft2DiscardRpcAcceptanceTest extends AcceptanceTestBase {

  @Test
  public void shouldDiscardVotes() throws IOException {
    final String[] validators = {"validator1", "validator3"};
    final BesuNode validator1 = besu.createIbft2NodeWithValidators("validator1", validators);
    final BesuNode validator2 = besu.createIbft2NodeWithValidators("validator2", validators);
    final BesuNode validator3 = besu.createIbft2NodeWithValidators("validator3", validators);
    cluster.start(validator1, validator2, validator3);

    validator1.execute(bftTransactions.createAddProposal(validator2));
    validator1.execute(bftTransactions.createRemoveProposal(validator3));
    validator1.verify(
        bft.pendingVotesEqual().addProposal(validator2).removeProposal(validator3).build());

    validator1.execute(bftTransactions.createDiscardProposal(validator2));
    validator1.verify(bft.pendingVotesEqual().removeProposal(validator3).build());

    validator1.execute(bftTransactions.createDiscardProposal(validator3));
    cluster.verify(bft.noProposals());
  }
}
