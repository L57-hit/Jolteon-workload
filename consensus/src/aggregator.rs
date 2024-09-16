use crate::config::{Committee, Stake};
use crate::consensus::Round;
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::{Timeout, Vote, ComVote, QC, ComQC, TC};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, Signature};
use std::collections::{HashMap, HashSet};

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

pub struct Aggregator<'a> {
    committee: &'a Committee,  // 使用 Committee 的引用
    votes_aggregators: HashMap<Round, HashMap<Digest, Box<QCMaker>>>,
    timeouts_aggregators: HashMap<Round, Box<TCMaker>>,
}

impl<'a> Aggregator<'a> {
    pub fn new(committee: &'a Committee) -> Self {
        Self {
            committee,
            votes_aggregators: HashMap::new(),
            timeouts_aggregators: HashMap::new(),
        }
    }

    pub fn add_vote(&mut self, vote: Vote) -> ConsensusResult<Option<QC>> {
        self.votes_aggregators
            .entry(vote.round)
            .or_insert_with(HashMap::new)
            .entry(vote.digest())
            .or_insert_with(|| Box::new(QCMaker::new()))
            .append(vote, self.committee)
    }

    pub fn add_timeout(&mut self, timeout: Timeout) -> ConsensusResult<Option<TC>> {
        self.timeouts_aggregators
            .entry(timeout.round)
            .or_insert_with(|| Box::new(TCMaker::new()))
            .append(timeout, self.committee)
    }

    pub fn cleanup(&mut self, round: &Round) {
        self.votes_aggregators.retain(|k, _| k >= round);
        self.timeouts_aggregators.retain(|k, _| k >= round);
    }
}

pub struct ComAggregator<'a> {
    committee: &'a Committee,  // 使用 Committee 的引用
    com_votes_aggregators: HashMap<Round, HashMap<Digest, Box<ComQCMaker>>>,
}

impl<'a> ComAggregator<'a> {
    pub fn new(committee: &'a Committee) -> Self {
        Self {
            committee,
            com_votes_aggregators: HashMap::new(),
        }
    }

    pub fn add_com_vote(&mut self, com_vote: ComVote) -> ConsensusResult<Option<ComQC>> {
        self.com_votes_aggregators
            .entry(com_vote.round)
            .or_insert_with(HashMap::new)
            .entry(com_vote.hash.clone())
            .or_insert_with(|| Box::new(ComQCMaker::new()))
            .append(com_vote, self.committee)
    }

    pub fn cleanup(&mut self, round: &Round) {
        self.com_votes_aggregators.retain(|k, _| k >= round);
    }
}


// pub struct Aggregator {
//     committee: Committee,
//     votes_aggregators: HashMap<Round, HashMap<Digest, Box<QCMaker>>>,
//     timeouts_aggregators: HashMap<Round, Box<TCMaker>>,
// }

// impl Aggregator {
//     pub fn new(committee: Committee) -> Self {
//         Self {
//             committee,
//             votes_aggregators: HashMap::new(),
//             timeouts_aggregators: HashMap::new(),
//         }
//     }

//     pub fn add_vote(&mut self, vote: Vote) -> ConsensusResult<Option<QC>> {
//         // TODO [issue #7]: A bad node may make us run out of memory by sending many votes
//         // with different round numbers or different digests.

//         // Add the new vote to our aggregator and see if we have a QC.
//         self.votes_aggregators
//             .entry(vote.round)
//             .or_insert_with(HashMap::new)
//             .entry(vote.digest())
//             .or_insert_with(|| Box::new(QCMaker::new()))
//             .append(vote, &self.committee)
//     }

//     pub fn add_timeout(&mut self, timeout: Timeout) -> ConsensusResult<Option<TC>> {
//         // TODO: A bad node may make us run out of memory by sending many timeouts
//         // with different round numbers.

//         // Add the new timeout to our aggregator and see if we have a TC.
//         self.timeouts_aggregators
//             .entry(timeout.round)
//             .or_insert_with(|| Box::new(TCMaker::new()))
//             .append(timeout, &self.committee)
//     }

//     pub fn cleanup(&mut self, round: &Round) {
//         self.votes_aggregators.retain(|k, _| k >= round);
//         self.timeouts_aggregators.retain(|k, _| k >= round);
//     }
// }

// pub struct ComAggregator {
//     committee: Committee,
//     com_votes_aggregators: HashMap<Round, HashMap<Digest, Box<ComQCMaker>>>, // 用于按轮次和区块哈希聚合ComVote
// }

// impl ComAggregator {
//     pub fn new(committee: Committee) -> Self {
//         Self {
//             committee,
//             com_votes_aggregators: HashMap::new(),
//         }
//     }

//     pub fn add_com_vote(&mut self, com_vote: ComVote) -> ConsensusResult<Option<ComQC>> {
//         // 将新的com_vote添加到聚合器中，并检查是否已经有足够的ComVote生成ComQC
//         self.com_votes_aggregators
//             .entry(com_vote.round)
//             .or_insert_with(HashMap::new)
//             .entry(com_vote.hash.clone()) // 使用ComVote中的hash作为键
//             .or_insert_with(|| Box::new(ComQCMaker::new()))
//             .append(com_vote, &self.committee)
//     }

//     pub fn cleanup(&mut self, round: &Round) {
//         // 清理旧轮次的投票数据，释放内存
//         self.com_votes_aggregators.retain(|k, _| k >= round);
//     }
// }


struct QCMaker {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl QCMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(&mut self, vote: Vote, committee: &Committee) -> ConsensusResult<Option<QC>> {
        let author = vote.author;

        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuse(author)
        );

        self.votes.push((author, vote.signature));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures QC is only made once.
            return Ok(Some(QC {
                hash: vote.hash.clone(),
                round: vote.round,
                votes: self.votes.clone(),
                block_author: vote.block_author,
            }));
        }
        Ok(None)
    }
}

pub struct ComQCMaker {
    weight: Stake,
    com_votes: Vec<(PublicKey, Signature)>,  // 存储ComVote中的公钥和签名
    used: HashSet<PublicKey>,                // 防止重复投票的集合
}

impl ComQCMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            com_votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// 尝试将一个 ComVote 附加到部分投票中，生成 ComQC。
    pub fn append(&mut self, com_vote: ComVote, committee: &Committee) -> ConsensusResult<Option<ComQC>> {
        let author = com_vote.author;

        // 确保该节点的首次投票有效，防止重复投票
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuse(author)
        );

        // 将投票者的公钥和签名添加到 com_votes 中
        self.com_votes.push((author, com_vote.signature));
        self.weight += committee.stake(&author);

        // 如果权重达到了委员会的门槛，则生成 ComQC
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0;  // 确保只生成一次 ComQC
            return Ok(Some(ComQC {
                hash: com_vote.hash.clone(),  // 使用 ComVote 中的 hash
                round: com_vote.round,        // 使用 ComVote 中的轮次
                block_author: com_vote.block_author,
                com_votes: self.com_votes.clone(),  // 收集到的 ComVote
            }));
        }

        Ok(None)  // 如果未达到门槛，则不生成 ComQC
    }
}


struct TCMaker {
    weight: Stake,
    votes: Vec<(PublicKey, Signature, Round)>,
    used: HashSet<PublicKey>,
}

impl TCMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        timeout: Timeout,
        committee: &Committee,
    ) -> ConsensusResult<Option<TC>> {
        let author = timeout.author;

        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuse(author)
        );

        // Add the timeout to the accumulator.
        self.votes
            .push((author, timeout.signature, timeout.high_qc.round));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures TC is only created once.
            return Ok(Some(TC {
                round: timeout.round,
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}
