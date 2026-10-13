use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginOutput {
    pub username: String,
    /// The device the browser signed in from, when it showed a certificate of one.
    pub device: Option<String>,
}

pub fn valid(input: &LoginInput) -> bool {
    let username = input.username.trim();
    (3..=25).contains(&username.len()) && (8..=128).contains(&input.password.chars().count())
}
