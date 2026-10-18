use nas_os_gateway::copy_database;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

mod common;
use common::Database;

#[tokio::test]
async fn a_copy_made_while_the_gateway_is_in_use_opens_and_is_whole() {
    let database = Database::new();
    database.create_account().await;
    let pool = SqlitePoolOptions::new()
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&database.0)
                .journal_mode(SqliteJournalMode::Wal),
        )
        .await
        .expect("database");

    let mut writing = pool.begin().await.expect("transaction");
    sqlx::query("DELETE FROM accounts")
        .execute(&mut *writing)
        .await
        .expect("pending delete");

    let target = database.0.with_extension("copy.db");
    copy_database(&pool, &target).await.expect("copied");
    copy_database(&pool, &target)
        .await
        .expect("copied again over the first");
    writing.rollback().await.expect("rollback");

    let copied = SqlitePoolOptions::new()
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&target)
                .read_only(true),
        )
        .await
        .expect("the copy opens");
    let check: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(&copied)
        .await
        .expect("checked");
    assert_eq!(check, "ok");
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
        .fetch_one(&copied)
        .await
        .expect("accounts");
    assert_eq!(accounts, 1);
    let _ = std::fs::remove_file(&target);
}
