use crate::aggregator::{Aggregator, ComAggregator};
use crate::config::Committee;
use crate::consensus::{ConsensusMessage, Round};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::mempool::MempoolDriver;
use crate::messages::{Block, Timeout, Vote, ComVote, QC, ComQC, TC};
use crate::proposer::ProposerMessage;
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use async_recursion::async_recursion;
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::SimpleSender;
use std::cmp::max;
use std::collections::VecDeque;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub struct Core {
    name: PublicKey,
    committee: Committee,
    store: Store,
    signature_service: SignatureService,
    leader_elector: LeaderElector,
    mempool_driver: MempoolDriver,
    synchronizer: Synchronizer,
    rx_message: Receiver<ConsensusMessage>,
    rx_loopback: Receiver<Block>,
    tx_proposer: Sender<ProposerMessage>,
    tx_commit: Sender<Block>,
    round: Round,
    last_voted_round: Round,
    last_committed_round: Round,
    high_qc: QC,
    timer: Timer,
    aggregator: Aggregator,
    com_aggregator: ComAggregator,
    network: SimpleSender,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        store: Store,
        leader_elector: LeaderElector,
        mempool_driver: MempoolDriver,
        synchronizer: Synchronizer,
        timeout_delay: u64,
        rx_message: Receiver<ConsensusMessage>,
        rx_loopback: Receiver<Block>,
        tx_proposer: Sender<ProposerMessage>,
        tx_commit: Sender<Block>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee: committee.clone(),
                signature_service,
                store,
                leader_elector,
                mempool_driver,
                synchronizer,
                rx_message,
                rx_loopback,
                tx_proposer,
                tx_commit,
                round: 1,
                last_voted_round: 0,
                last_committed_round: 0,
                high_qc: QC::genesis(),
                timer: Timer::new(timeout_delay),
                aggregator: Aggregator::new(committee),
                com_aggregator: ComAggregator::new(committee),
                network: SimpleSender::new(),
            }
            .run()
            .await
        });
    }

    async fn store_block(&mut self, block: &Block) {
        let key = block.digest().to_vec();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
    }

    fn increase_last_voted_round(&mut self, target: Round) {
        self.last_voted_round = max(self.last_voted_round, target);
    }

    async fn make_vote(&mut self, block: &Block) -> Option<Vote> {
        // Check if we can vote for this block.
        let safety_rule_1 = block.round > self.last_voted_round;
        let mut safety_rule_2 = block.qc.round + 1 == block.round;
        if let Some(ref tc) = block.tc {
            let mut can_extend = tc.round + 1 == block.round;
            can_extend &= block.qc.round >= *tc.high_qc_rounds().iter().max().expect("Empty TC");
            safety_rule_2 |= can_extend;
        }
        if !(safety_rule_1 && safety_rule_2) {
            return None;
        }

        // Ensure we won't vote for contradicting blocks.
        self.increase_last_voted_round(block.round);
        // TODO [issue #15]: Write to storage preferred_round and last_voted_round.
        Some(Vote::new(block, self.name, self.signature_service.clone()).await)
    }

            /// 根据收到的 QC 来生成 ComVote，先验证 QC 是否有效
async fn make_com_vote(&self, qc: &QC) -> Option<ComVote> {
    // 检查 QC 是否有效
    if let Err(e) = qc.verify(&self.committee) {
        // 如果 QC 无效，打印错误并返回 None
        println!("Invalid QC: {:?}", e);
        return None;
    }

    // 如果 QC 有效，生成 ComVote
    let com_vote = ComVote::new(
        qc,
        self.name,                              // 当前节点的公钥（投票人）
        self.signature_service.clone(),           // 签名服务，用于生成签名
    ).await;

    Some(com_vote)  // 返回生成的 ComVote
}

/// 处理接收到的 QC
async fn handle_qc(&mut self, qc: &QC) -> Option<ComVote> {
    // 处理QC以确保其合法性
    self.process_qc(qc).await;

    // 获取QC对应区块的作者节点
    let block_author = qc.block_author();

    // 如果 QC 不是由区块生成者发送，则不处理
    if block_author != self.name {
        return None;
    }

    // 尝试生成 ComVote
    if let Some(com_vote) = self.make_com_vote(qc).await {
        // 获取生成该区块的节点的地址信息
        let block_author_address = self
            .committee
            .address(&block_author)
            .expect("Block author not in committee");

        // 将 ComVote 消息序列化并发送给区块作者
        let message = bincode::serialize(&ConsensusMessage::ComVote(com_vote.clone()))
            .expect("Failed to serialize com vote");

        // 发送 ComVote 投票消息到区块作者
        self.network.send(block_author_address, Bytes::from(message)).await;

        // 返回生成的 ComVote
        return Some(com_vote);
    }

    None
}


    async fn commit(&mut self, block: Block) -> ConsensusResult<()> {
        if self.last_committed_round >= block.round {
            return Ok(());
        }

        // Ensure we commit the entire chain. This is needed after view-change.
        let mut to_commit = VecDeque::new();
        let mut parent = block.clone();
        while self.last_committed_round + 1 < parent.round {
            let ancestor = self
                .synchronizer
                .get_parent_block(&parent)
                .await?
                .expect("We should have all the ancestors by now");
            to_commit.push_front(ancestor.clone());
            parent = ancestor;
        }
        to_commit.push_front(block.clone());

        // Save the last committed block.
        self.last_committed_round = block.round;

        // Send all the newly committed blocks to the node's application layer.
        while let Some(block) = to_commit.pop_back() {
            if !block.payload.is_empty() {
                info!("Committed {}", block);

                #[cfg(feature = "benchmark")]
                for x in &block.payload {
                    // NOTE: This log entry is used to compute performance.
                    info!("Committed {} -> {:?}", block, x);
                }
            }
            debug!("Committed {:?}", block);
            if let Err(e) = self.tx_commit.send(block).await {
                warn!("Failed to send block through the commit channel: {}", e);
            }
        }
        Ok(())
    }

    fn update_high_qc(&mut self, qc: &QC) {
        if qc.round > self.high_qc.round {
            self.high_qc = qc.clone();
        }
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        warn!("Timeout reached for round {}", self.round);

        // Increase the last voted round.
        self.increase_last_voted_round(self.round);

        // Make a timeout message.
        let timeout = Timeout::new(
            self.high_qc.clone(),
            self.round,
            self.name,
            self.signature_service.clone(),
        )
        .await;
        debug!("Created {:?}", timeout);

        // Reset the timer.
        self.timer.reset();

        // Broadcast the timeout message.
        debug!("Broadcasting {:?}", timeout);
        let addresses = self
            .committee
            .broadcast_addresses(&self.name)
            .into_iter()
            .map(|(_, x)| x)
            .collect();
        let message = bincode::serialize(&ConsensusMessage::Timeout(timeout.clone()))
            .expect("Failed to serialize timeout message");
        self.network
            .broadcast(addresses, Bytes::from(message))
            .await;

        // Process our message.
        self.handle_timeout(&timeout).await
    }

    #[async_recursion]
    async fn handle_vote(&mut self, vote: &Vote) -> ConsensusResult<()> {
        debug!("Processing {:?}", vote);
        if vote.round < self.round {
            return Ok(());
        }

        // Ensure the vote is well formed.
        vote.verify(&self.committee)?;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(qc) = self.aggregator.add_vote(vote.clone())? {
            debug!("Assembled {:?}", qc);

            // Process the QC.
            self.process_qc(&qc).await;

            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(None).await;
            }
        }
        Ok(())
    }

    async fn handle_com_vote(&mut self, com_vote: &ComVote) -> ConsensusResult<()> {
        // 记录正在处理的 com_vote
        debug!("Processing {:?}", com_vote);
        
        // 如果接收到的 com vote 所属轮次小于当前轮次，直接返回
        if com_vote.round < self.round {
            return Ok(());
        }
    
        // 确保 com vote 结构的正确性
        com_vote.verify(&self.committee)?;
    
        // 将新的 com vote 添加到 com vote 聚合器中，并检查是否有足够的票生成 ComQC
        if let Some(com_qc) = self.com_aggregator.add_com_vote(com_vote.clone())? {
            debug!("Assembled ComQC {:?}", com_qc);
    
            // 如果生成了 com_qc，则处理它
            self.handle_com_qc(com_qc.clone()).await;
    
            // 使用现有的消息发送机制发送 ComQC 给其他节点
            debug!("Broadcasting ComQC {:?}", com_qc);
    
            // 获取要广播的地址列表
            let addresses = self
                .committee
                .broadcast_addresses(&self.name)
                .into_iter()
                .map(|(_, address)| address)
                .collect::<Vec<_>>();
    
            // 序列化 ComQC 消息
            let message = bincode::serialize(&ConsensusMessage::ComQC(com_qc.clone()))
                .expect("Failed to serialize ComQC message");
    
            // 广播消息
            self.network
                .broadcast(addresses, Bytes::from(message))
                .await;
    
            debug!("ComQC broadcasted successfully");
        }
    
        Ok(())
    }
    
    

    pub async fn handle_com_qc(&mut self, com_qc: ComQC) -> ConsensusResult<()> {
        let qc_block_id = &com_qc.hash;
    
        // Step 1: Verify that the ComQC is valid.
        com_qc.verify(&self.committee)?;
    
        // Step 2: Ensure the block corresponding to the ComQC exists.
        // 从存储中通过 hash 获取区块
        let block = match self.synchronizer.get_block_by_hash(&qc_block_id).await? {
            Some(block) => {
                // 找到了区块，处理 block
                block
            },
            None => {
                // 没有找到区块，返回 None 或者在这里处理未找到的情况
                info!("No block found for {:?}", qc_block_id);
                return Ok(());
            }
        };
    
        // Step 3: Commit the block and any uncommitted ancestors.
        info!("Committing block {:?} based on ComQC", qc_block_id);
        self.commit(block).await?;
    
        Ok(())
    }
       

    async fn handle_timeout(&mut self, timeout: &Timeout) -> ConsensusResult<()> {
        debug!("Processing {:?}", timeout);
        if timeout.round < self.round {
            return Ok(());
        }

        // Ensure the timeout is well formed.
        timeout.verify(&self.committee)?;

        // Process the QC embedded in the timeout.
        self.process_qc(&timeout.high_qc).await;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(tc) = self.aggregator.add_timeout(timeout.clone())? {
            debug!("Assembled {:?}", tc);

            // Try to advance the round.
            self.advance_round(tc.round).await;

            // Broadcast the TC.
            debug!("Broadcasting {:?}", tc);
            let addresses = self
                .committee
                .broadcast_addresses(&self.name)
                .into_iter()
                .map(|(_, x)| x)
                .collect();
            let message = bincode::serialize(&ConsensusMessage::TC(tc.clone()))
                .expect("Failed to serialize timeout certificate");
            self.network
                .broadcast(addresses, Bytes::from(message))
                .await;

            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(Some(tc)).await;
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn advance_round(&mut self, round: Round) {
        if round < self.round {
            return;
        }
        // Reset the timer and advance round.
        self.timer.reset();
        self.round = round + 1;
        debug!("Moved to round {}", self.round);

        // Cleanup the vote aggregator.
        self.aggregator.cleanup(&self.round);
    }

    #[async_recursion]
    async fn generate_proposal(&mut self, tc: Option<TC>) {
        self.tx_proposer
            .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc))
            .await
            .expect("Failed to send message to proposer");
    }

    async fn cleanup_proposer(&mut self, b0: &Block, b1: &Block, block: &Block) {
        let digests = b0
            .payload
            .iter()
            .cloned()
            .chain(b1.payload.iter().cloned())
            .chain(block.payload.iter().cloned())
            .collect();
        self.tx_proposer
            .send(ProposerMessage::Cleanup(digests))
            .await
            .expect("Failed to send message to proposer");
    }

    async fn process_qc(&mut self, qc: &QC) {
        self.advance_round(qc.round).await;
        self.update_high_qc(qc);
    }

    #[async_recursion]
    async fn process_block(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);

        // Let's see if we have the last three ancestors of the block, that is:
        //      b0 <- |qc0; b1| <- |qc1; block|
        // If we don't, the synchronizer asks for them to other nodes. It will
        // then ensure we process both ancestors in the correct order, and
        // finally make us resume processing this block.
        let (b0, b1) = match self.synchronizer.get_ancestors(block).await? {
            Some(ancestors) => ancestors,
            None => {
                debug!("Processing of {} suspended: missing parent", block.digest());
                return Ok(());
            }
        };

        // Store the block only if we have already processed all its ancestors.
        self.store_block(block).await;

        self.cleanup_proposer(&b0, &b1, block).await;

        // Check if we can commit the head of the 2-chain.
        // Note that we commit blocks only if we have all its ancestors.
// if b0.round + 1 == b1.round {
//     self.mempool_driver.cleanup(b0.round).await;
//     self.commit(b0).await?;
// }

        // Ensure the block's round is as expected.
        // This check is important: it prevents bad leaders from producing blocks
        // far in the future that may cause overflow on the round number.
        if block.round != self.round {
            return Ok(());
        }
                // 生成投票
if let Some(vote) = self.make_vote(block).await {
    debug!("Created {:?}", vote);
    
    // 获取下一个轮次的领导者
    let next_leader = self.leader_elector.get_leader(self.round + 1);
    let current_leader = block.author; // 当前区块的领导者

    // 发送投票给下一个轮次的领导者
    if next_leader == self.name {
        self.handle_vote(&vote).await?;
    } else {
        debug!("Sending {:?} to {}", vote, next_leader);
        let address = self
            .committee
            .address(&next_leader)
            .expect("The next leader is not in the committee");
        let message = bincode::serialize(&ConsensusMessage::Vote(vote.clone()))
            .expect("Failed to serialize vote");
        self.network.send(address, Bytes::from(message)).await;
    }

    // 发送投票给当前区块的领导者
    if current_leader != self.name {
        debug!("Sending {:?} to current leader {}", vote, current_leader);
        let address = self
            .committee
            .address(&current_leader)
            .expect("The current leader is not in the committee");
        let message = bincode::serialize(&ConsensusMessage::Vote(vote))
            .expect("Failed to serialize vote");
        self.network.send(address, Bytes::from(message)).await;
    }
}

        // See if we can vote for this block.
        // if let Some(vote) = self.make_vote(block).await {
        //     debug!("Created {:?}", vote);
        //     let next_leader = self.leader_elector.get_leader(self.round + 1);
        //     if next_leader == self.name {
        //         self.handle_vote(&vote).await?;
        //     } else {
        //         debug!("Sending {:?} to {}", vote, next_leader);
        //         let address = self
        //             .committee
        //             .address(&next_leader)
        //             .expect("The next leader is not in the committee");
        //         let message = bincode::serialize(&ConsensusMessage::Vote(vote))
        //             .expect("Failed to serialize vote");
        //         self.network.send(address, Bytes::from(message)).await;
        //     }
        // }
        Ok(())
    }

  

    async fn handle_proposal(&mut self, block: &Block) -> ConsensusResult<()> {
        let digest = block.digest();

        // Ensure the block proposer is the right leader for the round.
        ensure!(
            block.author == self.leader_elector.get_leader(block.round),
            ConsensusError::WrongLeader {
                digest,
                leader: block.author,
                round: block.round
            }
        );

        // Check the block is correctly formed.
        block.verify(&self.committee)?;

        // Process the QC. This may allow us to advance round.
        self.process_qc(&block.qc).await;

        // Process the TC (if any). This may also allow us to advance round.
        if let Some(ref tc) = block.tc {
            self.advance_round(tc.round).await;
        }

        // Let's see if we have the block's data. If we don't, the mempool
        // will get it and then make us resume processing this block.
        if !self.mempool_driver.verify(block.clone()).await? {
            debug!("Processing of {} suspended: missing payload", digest);
            return Ok(());
        }

        // All check pass, we can process this block.
        self.process_block(block).await
    }

    async fn handle_tc(&mut self, tc: TC) -> ConsensusResult<()> {
        tc.verify(&self.committee)?;
        if tc.round < self.round {
            return Ok(());
        }
        self.advance_round(tc.round).await;
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(Some(tc)).await;
        }
        Ok(())
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
        // Also, schedule a timer in case we don't hear from the leader.
        self.timer.reset();
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(None).await;
        }

        // This is the main loop: it processes incoming blocks and votes,
        // and receive timeout notifications from our Timeout Manager.
        loop {
            let result = tokio::select! {
                Some(message) = self.rx_message.recv() => match message {
                    ConsensusMessage::Propose(block) => self.handle_proposal(&block).await,
                    ConsensusMessage::Vote(vote) => self.handle_vote(&vote).await,
                    ConsensusMessage::Timeout(timeout) => self.handle_timeout(&timeout).await,
                    ConsensusMessage::TC(tc) => self.handle_tc(tc).await,
                    _ => panic!("Unexpected protocol message")
                },
                Some(block) = self.rx_loopback.recv() => self.process_block(&block).await,
                () = &mut self.timer => self.local_timeout_round().await,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}
