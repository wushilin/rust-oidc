//! Applied migrations, pinned to what the deployed service recorded.
//!
//! sqlx stores each applied migration's version, description and SHA-384
//! checksum, and refuses to start when a file of that number differs. That
//! failure used to be found on the server: the deployed service had applied
//! "remember" as version 20 while `main` numbered it 21, and a build of `main`
//! would not start there. These tests find such a mismatch in CI instead.
//!
//! The checksums are copied from `_sqlx_migrations` on the deployed SQLite
//! database (gate.wushilin.net), taken 2026-11-04, after its records were
//! aligned with `main` (decision 48). They are written out by hand
//! on purpose: an applied migration never changes, so neither may these. Add a
//! line when a migration is first deployed; never edit one.

use std::collections::BTreeMap;

/// (version, description, checksum) of every migration applied on the deployed
/// service, oldest first.
const DEPLOYED_SQLITE: &[(i64, &str, &str)] = &[
    (
        1,
        "init",
        "3b2b91bb3aa70b5255305e093c175ac6fbe7f39689c7d8dffb9939af46b0345733c8ce5c20bbe2772b6a900f09d0ac61",
    ),
    (
        2,
        "user signin",
        "65a572693d26f8ab4c6c3ef527092be2126474dd9189acb6e24d9bdb4ef3870c96752e6abea5bcb102a52e8adb0c3278",
    ),
    (
        3,
        "device code",
        "65a75c63e0d45c9b644a22a0c175b93465a60b6fc2592d88a2409d86763d5a082d402a847c09e9b496b3a1751670f854",
    ),
    (
        4,
        "app key credentials",
        "4a79cb018774f573676b4c26cb91d810cbee3b96abca64984bca844358729be3da712f667c3930d782bf20a24bf59e35",
    ),
    (
        5,
        "password grant",
        "308c65e515db63a962cc71edcacff2d1e1da8368323cc45caf01cba04843049730c1eea9ac9a31554d4646c0af367346",
    ),
    (
        6,
        "admin rbac",
        "eaefcaba77c46d718da57aed3bdde5dc47d65ffa901b29d0812a0d3b47862fb7ad4f4d9c5887a9dd6daf9e2ce4abbf77",
    ),
    (
        7,
        "case normalisation",
        "b4962802f319eec32275df2159d2f1202d7fd39b942c6e39e54d2c5877f3f9ec22bcaec72bf6194f007365fe2ff8b361",
    ),
    (
        8,
        "key rotation lock",
        "c47722ff10c05339d1a1d52b2fd3a5086da578f51e1a1ff846ae8eb81ff5e8c3d1ce7edaec86a6e1dec5d4d265e4970d",
    ),
    (
        9,
        "audit log indexes",
        "e8da7e268e942b164bf79219298580e5e225e1b58ae91dbb5fa2c83a7666fcfe10a72f97baf82b35dee37575946ade5f",
    ),
    (
        10,
        "implicit flow",
        "52d35a82ee350ae240761225a59e63c40703a9652b3fc1b5c5df8d99608b44f61e34b3196c1850aa1ca444ee8cf238c0",
    ),
    (
        11,
        "flow test",
        "cfb5be5662da63baca84cf032606be61a9e0662b4537c06f276d59b4d6c5500e4bcf16f6798f859fc371209b49d7d6b5",
    ),
    (
        12,
        "console roles",
        "f758dc5bd3db8bde1bdcc92d592dfd93a4ba3e6adbad7d38df731671345e3dba3dfa5c5f568bbfaae091630147ee0ad3",
    ),
    (
        13,
        "app assignments",
        "18a9fb77c8241f4d45a48efc347ca511f60070436b031016d9271af45dd578b3c2e9708901c72391662227ee03dcfafd",
    ),
    (
        14,
        "deleted groups",
        "f836394b7134bd250ff40868961b130cb8e089bd181febcdbc89e83cf37e5453abefaa53bdd535bb42d673bc38a62702",
    ),
    (
        15,
        "mfa",
        "796d528275451aff0649e706ed74f92e0087343ef90feca8ff90af1e62e34d7b298ecaf8c36432a3b30ee13d1b97fb11",
    ),
    (
        16,
        "password change",
        "a45dcbd719984027f3e042f1815eb755b0fe62cb1d5f0cabb57bbd4658ef45379dfa4773cbce62ca1600353fcc1f6cf8",
    ),
    (
        17,
        "cross tenant",
        "da2085732ebf7c2dc7f23a2143b5c1b45aae4988104ee0f31301190a939ba0e025f73bab7237ee555121aff659cda62e",
    ),
    (
        18,
        "txn locks",
        "ed3190734026e47e6498e8645084275bc9eddab07785e5cacefa2755db1b4839ff3eb4fc4f40e49ec9ccb63e302fcced",
    ),
    (
        19,
        "auth api",
        "d892c852a9c6ff1e299d3c50ae29fb7996f141411a9f6ab42307ba37d64d1e4eb30e0f68b8f52abaa277f00e185b809f",
    ),
    (
        20,
        "group claims nesting",
        "e4a16ee310057af8785ac2389e06c9574fa8ba5b4ca16f5808d88e35dac8217502c82fc07f1d45d1eb8508d6b95424cd",
    ),
    (
        21,
        "remember",
        "bb360498c05b2d687fa6e8f7f49babe04e155d89361eff4f266335191573e94c64becbb6950261774fb64f06453aba9f",
    ),
];

/// version -> (description, checksum), as the server's migrator resolves them.
fn resolved(migrator: &sqlx::migrate::Migrator) -> BTreeMap<i64, (String, String)> {
    migrator
        .iter()
        .map(|m| (m.version, (m.description.to_string(), hex::encode(&*m.checksum))))
        .collect()
}

fn sqlite() -> BTreeMap<i64, (String, String)> {
    resolved(&sqlx::migrate!("./migrations/sqlite"))
}

/// What the deployed service applied is exactly what this build would find under
/// the same numbers: otherwise it refuses to start there.
#[test]
fn every_deployed_migration_is_unchanged_under_its_number() {
    let here = sqlite();
    for (version, description, checksum) in DEPLOYED_SQLITE {
        let Some((desc, sum)) = here.get(version) else {
            panic!("migration {version} ({description}) is applied on the deployed service but missing here");
        };
        assert_eq!(desc, description, "migration {version} was renamed");
        assert_eq!(
            sum, checksum,
            "migration {version} ({description}) differs from what the deployed service applied"
        );
    }
}

/// The three engines number their migrations the same way, with the same
/// names, from 1 with no gaps: they are translations of one history.
#[test]
fn the_three_engines_have_the_same_numbered_history() {
    let sqlite = sqlite();
    let postgres = resolved(&sqlx::migrate!("./migrations/postgres"));
    let mysql = resolved(&sqlx::migrate!("./migrations/mysql"));
    let names = |m: &BTreeMap<i64, (String, String)>| -> Vec<(i64, String)> {
        m.iter().map(|(v, (d, _))| (*v, d.clone())).collect()
    };
    assert_eq!(names(&sqlite), names(&postgres), "SQLite and Postgres differ");
    assert_eq!(names(&sqlite), names(&mysql), "SQLite and MySQL differ");
    let versions: Vec<i64> = sqlite.keys().copied().collect();
    let expected: Vec<i64> = (1..=versions.len() as i64).collect();
    assert_eq!(versions, expected, "migration numbers have a gap or a repeat");
}
