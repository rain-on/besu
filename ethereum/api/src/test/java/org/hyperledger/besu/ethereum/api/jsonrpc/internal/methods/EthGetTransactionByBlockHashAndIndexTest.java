/*
 * Copyright 2018 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.hyperledger.besu.ethereum.api.jsonrpc.internal.methods;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequest;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.parameters.JsonRpcParameter;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.queries.BlockchainQueries;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcSuccessResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.results.Quantity;
import org.hyperledger.besu.util.bytes.Bytes32;
import org.hyperledger.besu.util.bytes.BytesValue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class EthGetTransactionByBlockHashAndIndexTest {
  private EthGetTransactionByBlockHashAndIndex method;
  @Mock private BlockchainQueries blockchain;

  @Test
  public void shouldReturnNullWhenBlockHashDoesNotExist() {
    method = new EthGetTransactionByBlockHashAndIndex(blockchain, new JsonRpcParameter());
    Bytes32 hash = Hash.keccak256(BytesValue.wrap("horse".getBytes(UTF_8)));
    JsonRpcSuccessResponse response = (JsonRpcSuccessResponse) method.response(request(hash, 1));
    assertThat(response.getResult()).isEqualTo(null);
  }

  private JsonRpcRequest request(final Bytes32 hash, final long index) {
    return new JsonRpcRequest(
        "2.0",
        "eth_getTransactionByBlockHashAndIndex",
        new Object[] {String.valueOf(hash), Quantity.create(index)});
  }
}
