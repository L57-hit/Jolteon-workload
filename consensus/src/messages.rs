use crate::config::Committee;
use crate::consensus::Round;
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryInto;
use std::fmt;
//use log::{debug, error};

#[cfg(test)]
#[path = "tests/messages_tests.rs"]
pub mod messages_tests;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub qc: QC,
    pub tc: Option<TC>,
    pub author: PublicKey,
    pub round: Round,
    pub payload: Vec<Digest>,
    pub signature: Signature,
}

impl Block {
    pub async fn new(
        qc: QC,
        tc: Option<TC>,
        author: PublicKey,
        round: Round,
        payload: Vec<Digest>,
        mut signature_service: SignatureService,
    ) -> Self {
        let block = Self {
            qc,
            tc,
            author,
            round,
            payload,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(block.digest()).await;
        Self { signature, ..block }
    }

    pub fn genesis() -> Self {
        Block::default()
    }

    pub fn parent(&self) -> &Digest {
        &self.qc.hash
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        // Check the embedded QC.
        if self.qc != QC::genesis() {
            self.qc.verify(committee)?;
        }

        // Check the TC embedded in the block (if any).
        if let Some(ref tc) = self.tc {
            tc.verify(committee)?;
        }
        Ok(())
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.round.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        hasher.update(&self.qc.hash);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B({}, {}, {:?}, {})",
            self.digest(),
            self.author,
            self.round,
            self.qc,
            self.payload.iter().map(|x| x.size()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}", self.round)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub hash: Digest,
    pub round: Round,
    pub author: PublicKey,
    pub block_author: PublicKey,
    pub signature: Signature,
}

impl Vote {
    pub async fn new(
        block: &Block,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let vote = Self {
            hash: block.digest(),
            round: block.round,
            author,
            block_author: block.author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.hash);
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "V({}, {}, {})", self.author, self.round, self.hash)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ComVote {
    pub hash: Digest,        // 区块的哈希
    pub round: Round,        // 轮次
    pub author: PublicKey,   // 投票者的公钥
    pub block_author: PublicKey,
    pub signature: Signature,// 投票的签名
    //pub vote_type: String,   // 投票类型，区分普通 vote 和 com vote
}

impl ComVote {
    // 构造一个新的 ComVote 实例
    pub async fn new(
        qc: &QC,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let com_vote = Self {
            hash: qc.hash.clone(),
            round: qc.round,
            author,
            block_author: qc.block_author,
            signature: Signature::default(),
        };
        // 签名 QC 的哈希，标识这个 com vote
        let signature = signature_service.request_signature(com_vote.hash.clone()).await;
        
        // 返回包含签名的 ComVote
        Self { signature, ..com_vote }
    }
   

    // 验证 com vote 的正确性
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // 确保投票者在委员会中具有投票权
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // 验证签名的正确性
        self.signature.verify(&self.hash, &self.author)?;
        Ok(())
    }
}

impl Hash for ComVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.hash); // 使用区块的哈希
        hasher.update(&self.block_author);
        hasher.update(self.round.to_le_bytes()); // 使用轮次
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap()) // 返回32字节的哈希值
    }
}

impl fmt::Debug for ComVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f, 
            "ComVote({}, {}, {})", 
            self.author,  // 投票者
            self.round,   // 轮次
            self.hash     // 区块哈希
        )
    }
}


#[derive(Clone, Serialize, Deserialize, Default)]
pub struct QC {
    pub hash: Digest,
    pub round: Round,
    pub votes: Vec<(PublicKey, Signature)>,
    pub block_author: PublicKey,  // 添加这个字段来存储区块的作者
}

impl QC {
    pub fn genesis() -> Self {
        QC::default()
    }

    pub fn timeout(&self) -> bool {
        self.hash == Digest::default() && self.round != 0
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
            //debug!("Vote from authority {} with rights {} accepted", name, voting_rights);
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::QCRequiresQuorum
        );
        //debug!("Digest QC: {:?}", self.digest());  // 打印消息摘要
        // for (name, sig) in self.votes.iter() {
        //     debug!("Vote from authority {}: Signature {:?}", name, sig);
        // }
        // Check the signatures.
        Signature::verify_batch(&self.digest(), &self.votes).map_err(ConsensusError::from)
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.hash);
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "QC({}, {})", self.hash, self.round)
    }
}

impl PartialEq for QC {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.round == other.round
    }
}
impl QC {
    pub fn block_author(&self) -> PublicKey {
        self.block_author
    }
}


#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ComQC {
    pub hash: Digest,
    pub round: Round,
    pub com_votes: Vec<(PublicKey, Signature)>, // 由com vote构成的签名集合
    pub block_author: PublicKey  // 添加发送者字段
}

impl ComQC {

    // pub fn genesis() -> Self {
    //     ComQC::default()
    // }

    // pub fn timeout(&self) -> bool {
    //     self.hash == Digest::default() && self.round != 0
    // }
    // pub fn new(hash: Digest, round: Round, com_votes: Vec<(PublicKey, Signature)>, block_author: PublicKey) -> Self {
    //     Self {
    //         hash,
    //         round,
    //         com_votes,
    //         block_author,
    //     }
    // }
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // 初始化变量
        let mut weight = 0;
        let mut used = HashSet::new();
    
        // 遍历 `com_votes` 并检查投票的合法性
        for (name, _) in self.com_votes.iter() {
            //debug!("Checking vote from authority: {}", name);
    
            // 检查是否有重复的投票
            // if used.contains(name) {
            //     error!("Authority reused: {}", name);
            //     return Err(ConsensusError::AuthorityReuse(*name));
            // }
    
            // 检查投票者是否在委员会中
            let voting_rights = committee.stake(name);
            // if voting_rights == 0 {
            //     error!("Unknown authority: {}", name);
            //     return Err(ConsensusError::UnknownAuthority(*name));
            // }
    
            // 记录已使用的投票者
            used.insert(*name);
            weight += voting_rights;
            //debug!("ComVote from authority {} with rights {} accepted", name, voting_rights);
        }
    
        // 输出当前累积的权重
        //debug!("Total voting weight: {}", weight);
    
        // 检查是否达到了委员会的法定投票权重
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::QCRequiresQuorum
        );
    //     debug!("Quorum threshold reached");
    
    //      // 调试信息：打印批量签名验证的输入数据
    // debug!("Verifying batch signatures...");
    // debug!("ComQC for block: {:?}", self.hash);
    //debug!("Digest ComQC: {:?}", self.digest());  // 打印消息摘要

    // for (name, sig) in self.com_votes.iter() {
    //     debug!("ComVote from authority {}: Signature {:?}", name, sig);
    // }

    // let result = Signature::verify_batch(&self.hash.clone(), &self.com_votes);

    // if let Err(ref e) = result {
    //     error!("Signature verification failed: {:?}", e);
    // } else {
    //     debug!("Signature verification succeeded");
    // }

    // result.map_err(ConsensusError::from)
    Signature::verify_batch(&self.hash.clone(), &self.com_votes).map_err(ConsensusError::from)
    }
    
    // 验证 ComQC 的有效性
    // pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
    //     // 确保 ComQC 拥有足够多的 com votes
    //     let mut weight = 0;
    //     let mut used = HashSet::new();
    //     for (name, _) in self.com_votes.iter() {
    //         ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
    //         let voting_rights = committee.stake(name);
    //         ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
    //         used.insert(*name);
    //         weight += voting_rights;
    //     }
    //     //debug!("there?");

    //     ensure!(
    //         weight >= committee.quorum_threshold(),
    //         ConsensusError::QCRequiresQuorum
    //     );
    //     //debug!("weight is: {}", weight);
    //     //debug!("here?");
    //     // 检查签名的有效性
    //     //Signature::verify_batch(&self.digest(), &self.com_votes).map_err(ConsensusError::from)
    //     let result = Signature::verify_batch(&self.digest(), &self.com_votes);
    
    // // 如果批量验证出错，打印错误信息
    // if let Err(ref e) = result {
    //     error!("Signature verification failed: {:?}", e);
    // }

    // // 将CryptoError映射为ConsensusError，并返回结果
    // result.map_err(ConsensusError::from)
    // }

    // 生成唯一的摘要，用于签名验证
    // pub fn digest(&self) -> Digest {
    //     let mut hasher = Sha512::new();
    //     hasher.update(&self.hash);
    //     hasher.update(&self.block_author);
    //     hasher.update(self.round.to_le_bytes());
    //     Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    // }
}

impl fmt::Debug for ComQC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "ComQC({}, {},)", self.hash, self.round)
    }
}

impl PartialEq for ComQC {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.round == other.round
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    pub high_qc: QC,
    pub round: Round,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Timeout {
    pub async fn new(
        high_qc: QC,
        round: Round,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let timeout = Self {
            high_qc,
            round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(timeout.digest()).await;
        Self {
            signature,
            ..timeout
        }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        // Check the embedded QC.
        if self.high_qc != QC::genesis() {
            self.high_qc.verify(committee)?;
        }
        Ok(())
    }
}

impl Hash for Timeout {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.high_qc.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TV({}, {}, {:?})", self.author, self.round, self.high_qc)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TC {
    pub round: Round,
    pub votes: Vec<(PublicKey, Signature, Round)>,
}

impl TC {
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _, _) in self.votes.iter() {
            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::TCRequiresQuorum
        );

        // Check the signatures.
        for (author, signature, high_qc_round) in &self.votes {
            let mut hasher = Sha512::new();
            hasher.update(self.round.to_le_bytes());
            hasher.update(high_qc_round.to_le_bytes());
            let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
            signature.verify(&digest, author)?;
        }
        Ok(())
    }

    pub fn high_qc_rounds(&self) -> Vec<Round> {
        self.votes.iter().map(|(_, _, r)| r).cloned().collect()
    }
}

impl fmt::Debug for TC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TC({}, {:?})", self.round, self.high_qc_rounds())
    }
}
