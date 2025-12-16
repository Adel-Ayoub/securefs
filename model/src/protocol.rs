use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub enum Cmd {
    Cat,
    Cd,
    Delete,
    Echo,
    Login,
    Ls,
    Mkdir,
    GetEncryptedFile,
    Mv,
    Scan,
    NewConnection,
    NewGroup,
    NewUser,
    Failure,
    Pwd,
    Touch,
    Chmod,
    Logout,
    #[default]
    Invalid,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppMessage {
    pub cmd: Cmd,
    pub data: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Path {
    pub path: Vec<(bool, String)>,
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut path_string = self
            .path
            .iter()
            .map(|x| x.1.clone())
            .filter(|x| x != "/")
            .collect::<Vec<String>>()
            .join("/");

        path_string.insert_str(0, "/");
        write!(f, "{}", path_string)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FNode {
    pub id: i64,
    pub name: String,
    pub path: String,
    pub owner: String,
    pub hash: String,
    pub parent: String,
    pub dir: bool,
    pub u: i16,
    pub g: i16,
    pub o: i16,
    pub children: Vec<String>,
    pub encrypted_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub id: i64,
    pub user_name: String,
    pub group_name: Option<String>,
    pub key: String,
    pub salt: String,
    pub is_admin: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Group {
    pub id: i64,
    pub users: Vec<String>,
    pub g_name: String,
}

