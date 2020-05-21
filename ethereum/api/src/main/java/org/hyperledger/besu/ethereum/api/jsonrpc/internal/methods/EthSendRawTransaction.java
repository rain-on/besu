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
package org.hyperledger.besu.ethereum.api.jsonrpc.internal.methods;

import org.hyperledger.besu.ethereum.api.jsonrpc.JsonRpcErrorConverter;
import org.hyperledger.besu.ethereum.api.jsonrpc.RpcMethod;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequestContext;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.exception.InvalidJsonRpcRequestException;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcError;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcErrorResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcSuccessResponse;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPool;
import org.hyperledger.besu.ethereum.mainnet.TransactionValidator.TransactionInvalidReason;
import org.hyperledger.besu.ethereum.mainnet.ValidationResult;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPException;

import java.util.function.Supplier;

import com.google.common.base.Suppliers;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public class EthSendRawTransaction implements JsonRpcMethod {

  private static final Logger LOG = LogManager.getLogger();
  private final boolean sendEmptyHashOnInvalidBlock;

  private final Supplier<TransactionPool> transactionPool;

  public EthSendRawTransaction(final TransactionPool transactionPool) {
    this(Suppliers.ofInstance(transactionPool), false);
  }

  public EthSendRawTransaction(
      final Supplier<TransactionPool> transactionPool, final boolean sendEmptyHashOnInvalidBlock) {
    this.transactionPool = transactionPool;
    this.sendEmptyHashOnInvalidBlock = sendEmptyHashOnInvalidBlock;
  }

  @Override
  public String getName() {
    return RpcMethod.ETH_SEND_RAW_TRANSACTION.getMethodName();
  }

  @Override
  public JsonRpcResponse response(final JsonRpcRequestContext requestContext) {
    LOG.debug("Received raw transaction");
    if (requestContext.getRequest().getParamLength() != 1) {
      return new JsonRpcErrorResponse(
          requestContext.getRequest().getId(), JsonRpcError.INVALID_PARAMS);
    }
    final String rawTransaction = requestContext.getRequiredParameter(0, String.class);
    LOG.debug("Decoding Transaction");
    final Transaction transaction;
    try {
      transaction = decodeRawTransaction(rawTransaction);
    } catch (final InvalidJsonRpcRequestException e) {
      return new JsonRpcErrorResponse(
          requestContext.getRequest().getId(), JsonRpcError.INVALID_PARAMS);
    }
    LOG.debug("Transaction decoded");

    final ValidationResult<TransactionInvalidReason> validationResult =
        transactionPool.get().addLocalTransaction(transaction);
    LOG.debug("Transaction validated and added to transaction pool.");
    return validationResult.either(
        () ->
            new JsonRpcSuccessResponse(
                requestContext.getRequest().getId(), transaction.getHash().toString()),
        errorReason ->
            sendEmptyHashOnInvalidBlock
                ? new JsonRpcSuccessResponse(
                    requestContext.getRequest().getId(), Hash.EMPTY.toString())
                : new JsonRpcErrorResponse(
                    requestContext.getRequest().getId(),
                    JsonRpcErrorConverter.convertTransactionInvalidReason(errorReason)));
  }

  private Transaction decodeRawTransaction(final String hash)
      throws InvalidJsonRpcRequestException {
    try {
      return Transaction.readFrom(RLP.input(Bytes.fromHexString(hash)));
    } catch (final IllegalArgumentException | RLPException e) {
      LOG.debug(e);
      throw new InvalidJsonRpcRequestException("Invalid raw transaction hex", e);
    }
  }
}
